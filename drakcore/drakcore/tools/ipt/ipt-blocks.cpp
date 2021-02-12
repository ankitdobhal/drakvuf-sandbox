#include <iostream>
#include <memory>
#include <functional>
#include <string>
#include <fstream>
#include <streambuf>
#include <optional>
#include <vector>

#include <cstdint>
#include <intel-pt.h>

#define PTW_CURRENT_CR3  (0xC3000000)
#define PTW_CURRENT_TID  (0x1D000000)
#define PTW_EVENT_ID     (0xCC000000)
#define PTW_ERROR_EMPTY  (0xBAD10000)

bool is_drakvuf_ptwrite(const struct pt_event *event)
{
	if (event->type != ptev_ptwrite) return false;

	uint32_t cmd = event->variant.ptwrite.payload >> 32;

	switch (cmd) {
	case PTW_CURRENT_CR3:
	case PTW_CURRENT_TID:
	case PTW_EVENT_ID:
		return true;
	}

	return false;
}

class Image {
public:
    Image()
    {
        section_cache_ = std::unique_ptr<struct pt_image_section_cache, ImageSecDeleter>(
            pt_iscache_alloc(nullptr),
            pt_iscache_free
        );

        image_ = std::unique_ptr<struct pt_image, ImageDeleter>(
            pt_image_alloc(nullptr),
            pt_image_free
        );
    }

	int map_page(const std::string &fname, uint64_t address)
    {
		const auto isid = pt_iscache_add_file(
			section_cache_.get(), fname.c_str(), 0, 0x1000, address
		);
		if (isid < 0) {
			std::cerr << "Failed to map " << fname << " at 0x" << std::hex << address << "\n";
			return -1;
		}
		const auto err = pt_image_add_cached(image_.get(), section_cache_.get(), isid, nullptr);
		if (err < 0) {
			std::cerr << "Failed to map " << fname << " at 0x" << std::hex << address << "\n";
			return -1;
		}
		return 0;
	}

    struct pt_image* get_pt_image() const {
        return image_.get();
    }

    uint32_t cr3_value;

private:
    using ImageSecDeleter = std::function<void(struct pt_image_section_cache*)>;
    using ImageDeleter = std::function<void(struct pt_image*)>;

    std::unique_ptr<struct pt_image_section_cache, ImageSecDeleter> section_cache_;
    std::unique_ptr<struct pt_image, ImageDeleter> image_;

};


class Decoder
{
public:
	Decoder()
    {
        pt_config_init(&config_);
	}

    void load_pt(const std::string &filename) {
        std::ifstream stream{filename, std::ios::binary};

        stream.seekg(0, std::ios::end);   
        proc_trace_.reserve(stream.tellg());
        stream.seekg(0, std::ios::beg);

        proc_trace_.assign(std::istreambuf_iterator<char>{stream},
                           std::istreambuf_iterator<char>{});

		config_.begin = proc_trace_.data();
		config_.end = config_.begin + proc_trace_.size();
    }

	void decode_stream(const Image *image) {
        using BlockDecDeleter = std::function<void(struct pt_block_decoder*)>;
		auto block_dec = std::unique_ptr<struct pt_block_decoder, BlockDecDeleter>(
		    pt_blk_alloc_decoder(&config_),
		    pt_blk_free_decoder
		);

		pt_blk_set_image(block_dec.get(), image->get_pt_image());

		uint64_t sync = 0;

		for (;;) {
            auto decoder = block_dec.get();

			struct pt_block block;
			block.ip = 0;
			block.ninsn = 0;

			int status = pt_blk_sync_forward(decoder);
			if (status < 0) {
				// End of stream
				if (status == -pte_eos) break;

				std::cerr << "Failed to sync forward" << status << "\n";

				uint64_t new_sync;
				int errcode = pt_blk_get_offset(decoder, &new_sync);
				if (errcode < 0 || (new_sync <= sync)) break;
				sync = new_sync;
				continue;
			}

			for (;;) {
				status = process_events(decoder, status);
				if (status < 0) {
					break;
				}
				if (status & pts_eos) {
					if (!(status & pts_ip_suppressed))
						std::cout << "[end of trace]\n";

					status = -pte_eos;
					break;
				}
				status = pt_blk_next(decoder, &block, sizeof(block));
				if (block.ninsn && current_cr3_ == image->cr3_value) {
                    process_block(&block);
				}
				if (status < 0) break;
			}

		}
	}

	int process_events(struct pt_block_decoder *decoder, int status) {
		while (status & pts_event_pending) {
			struct pt_event event;
			status = pt_blk_event(decoder, &event, sizeof(event));
			if (status < 0) return status;
			process_event(&event);
		}		
		return status;
	}

    void process_block(const struct pt_block *block) {
        std::cout << "[block 0x" << std::hex << block->ip << std::dec << "]\n"; 		
    }
	
	void process_event(const struct pt_event *event) {
		switch (event->type) {
		case ptev_ptwrite:
			if (is_drakvuf_ptwrite(event)){
				uint32_t cmd = event->variant.ptwrite.payload >> 32;
				uint32_t data = event->variant.ptwrite.payload & 0xffffffff;

				if (cmd == PTW_CURRENT_CR3) {
					current_cr3_ = data;
				}
                if (!show_drakvuf_) break;

				switch (cmd) {
				case PTW_CURRENT_CR3:
					std::cout << "[drakvuf cr3: 0x" << std::hex << data << std::dec << "]\n";
					break;
				case PTW_CURRENT_TID:
					std::cout << "[drakvuf tid: " << data << "]\n";
					break;
				case PTW_EVENT_ID:
					std::cout << "[drakvuf event: " << data << "]\n";
					break;
				default:
					std::cout << "[ptwrite: " << std::hex << event->variant.ptwrite.payload << std::dec << "]\n";
				}
			}
			break;
		case ptev_enabled:
		case ptev_disabled:
		case ptev_async_disabled:
		case ptev_async_branch:
		case ptev_paging:
		case ptev_async_paging:
		case ptev_overflow:
		case ptev_exec_mode:
		case ptev_tsx:
		case ptev_stop:
		case ptev_vmcs:
		case ptev_async_vmcs:
		case ptev_exstop:
		case ptev_mwait:
		case ptev_pwre:
		case ptev_pwrx:
		case ptev_mnt:
		case ptev_tick:
		case ptev_cbr:
			break;
		}
	}

    bool show_drakvuf_ = false;

private:
	struct pt_config config_;
    std::vector<uint8_t> proc_trace_;

	uint32_t current_cr3_;
};

int main(int argc, char *argv[])
{
    Decoder decoder{};
    Image image{};

	std::optional<std::string> pt_file;
	std::optional<uint64_t> cr3_filter;

	for (int i = 1; i < argc; i++) {
		const auto arg = std::string(argv[i]);
		const bool has_more_args = i + 1 < argc;
		if (arg == "--pt") {
			if (!has_more_args) {
				std::cerr << "Missing argument for --pt\n";
				return 1;
			}
            i++;
            pt_file = std::string(argv[i]);
		} else if (arg == "--cr3") {
			if (!has_more_args) {
				std::cerr << "Missing argument for --cr3\n";
                return 1;
			}
            i++;
            cr3_filter = std::stoul(std::string(argv[i]), 0, 0);
		} else if (arg == "--raw") {
			if (!has_more_args) {
				std::cerr << "Missing argument for --raw\n";
                return 1;
			}
            i++;
            const auto arg = std::string(argv[i]);
            const auto fname = arg.substr(0, arg.find_first_of(":"));
            const auto addr = arg.substr(arg.find_first_of(":") + 1);
            const uint64_t virt_addr = std::stoull(addr, 0, 0);

            std::cerr << "Mapping " << fname << " at " << std::hex << virt_addr << std::dec << "\n";
            if (image.map_page(fname, virt_addr) != 0) {
                return 1;
            }
		} else if (arg == "--show-drakvuf") {
            decoder.show_drakvuf_ = true;
        } else {
			std::cerr << "Unknown argument " << arg << "\n";
			return 1;
		}
	}

	if (!pt_file) {
        std::cerr << "Missing --pt [ipt_trace_file]\n";
        return 1;
    }
    if (!cr3_filter) {
        std::cerr << "Missing --cr3 [cr3_filter]\n";
        return 1;
    }
        
    decoder.load_pt(*pt_file);
    image.cr3_value = *cr3_filter;
    decoder.decode_stream(&image);
}
