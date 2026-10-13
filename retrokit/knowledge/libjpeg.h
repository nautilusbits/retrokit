/* IJG libjpeg 6/6b interface (IJG license), the commonly called part of jpeglib.h. The big
 * compress/decompress structures are left opaque: their layout depends on the build's
 * jmorecfg.h. Applied to the functions the jpeg-6b signatures name.
 */

struct jpeg_compress_struct;
struct jpeg_decompress_struct;
struct jpeg_common_struct;
struct jpeg_error_mgr;
typedef struct jpeg_compress_struct *j_compress_ptr;
typedef struct jpeg_decompress_struct *j_decompress_ptr;
typedef struct jpeg_common_struct *j_common_ptr;
typedef unsigned char JSAMPLE;
typedef JSAMPLE *JSAMPROW;
typedef JSAMPROW *JSAMPARRAY;
typedef unsigned int JDIMENSION;
typedef int boolean;

struct jpeg_error_mgr *jpeg_std_error(struct jpeg_error_mgr *err);
void jpeg_CreateCompress(j_compress_ptr cinfo, int version, size_t structsize);
void jpeg_CreateDecompress(j_decompress_ptr cinfo, int version, size_t structsize);
void jpeg_destroy_compress(j_compress_ptr cinfo);
void jpeg_destroy_decompress(j_decompress_ptr cinfo);
void jpeg_stdio_dest(j_compress_ptr cinfo, FILE *outfile);
void jpeg_stdio_src(j_decompress_ptr cinfo, FILE *infile);
void jpeg_set_defaults(j_compress_ptr cinfo);
void jpeg_set_colorspace(j_compress_ptr cinfo, int colorspace);
void jpeg_default_colorspace(j_compress_ptr cinfo);
void jpeg_set_quality(j_compress_ptr cinfo, int quality, boolean force_baseline);
void jpeg_set_linear_quality(j_compress_ptr cinfo, int scale_factor, boolean force_baseline);
int jpeg_quality_scaling(int quality);
void jpeg_simple_progression(j_compress_ptr cinfo);
void jpeg_suppress_tables(j_compress_ptr cinfo, boolean suppress);
void jpeg_start_compress(j_compress_ptr cinfo, boolean write_all_tables);
JDIMENSION jpeg_write_scanlines(j_compress_ptr cinfo, JSAMPARRAY scanlines, JDIMENSION num_lines);
void jpeg_finish_compress(j_compress_ptr cinfo);
void jpeg_write_marker(j_compress_ptr cinfo, int marker, const unsigned char *dataptr, unsigned int datalen);
void jpeg_write_tables(j_compress_ptr cinfo);
int jpeg_read_header(j_decompress_ptr cinfo, boolean require_image);
boolean jpeg_start_decompress(j_decompress_ptr cinfo);
JDIMENSION jpeg_read_scanlines(j_decompress_ptr cinfo, JSAMPARRAY scanlines, JDIMENSION max_lines);
boolean jpeg_finish_decompress(j_decompress_ptr cinfo);
JDIMENSION jpeg_read_raw_data(j_decompress_ptr cinfo, void *data, JDIMENSION max_lines);
boolean jpeg_has_multiple_scans(j_decompress_ptr cinfo);
boolean jpeg_start_output(j_decompress_ptr cinfo, int scan_number);
boolean jpeg_finish_output(j_decompress_ptr cinfo);
boolean jpeg_input_complete(j_decompress_ptr cinfo);
int jpeg_consume_input(j_decompress_ptr cinfo);
void jpeg_calc_output_dimensions(j_decompress_ptr cinfo);
void jpeg_save_markers(j_decompress_ptr cinfo, int marker_code, unsigned int length_limit);
void jpeg_abort_compress(j_compress_ptr cinfo);
void jpeg_abort_decompress(j_decompress_ptr cinfo);
void jpeg_abort(j_common_ptr cinfo);
void jpeg_destroy(j_common_ptr cinfo);
boolean jpeg_resync_to_restart(j_decompress_ptr cinfo, int desired);
