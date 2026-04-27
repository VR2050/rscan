package com.googlecode.mp4parser.h264.model;

import com.snail.antifake.deviceid.ShellAdbUtils;

/* JADX INFO: loaded from: classes.dex */
public class VUIParameters {
    public AspectRatio aspect_ratio;
    public boolean aspect_ratio_info_present_flag;
    public BitstreamRestriction bitstreamRestriction;
    public boolean chroma_loc_info_present_flag;
    public int chroma_sample_loc_type_bottom_field;
    public int chroma_sample_loc_type_top_field;
    public boolean colour_description_present_flag;
    public int colour_primaries;
    public boolean fixed_frame_rate_flag;
    public boolean low_delay_hrd_flag;
    public int matrix_coefficients;
    public HRDParameters nalHRDParams;
    public int num_units_in_tick;
    public boolean overscan_appropriate_flag;
    public boolean overscan_info_present_flag;
    public boolean pic_struct_present_flag;
    public int sar_height;
    public int sar_width;
    public int time_scale;
    public boolean timing_info_present_flag;
    public int transfer_characteristics;
    public HRDParameters vclHRDParams;
    public int video_format;
    public boolean video_full_range_flag;
    public boolean video_signal_type_present_flag;

    public static class BitstreamRestriction {
        public int log2_max_mv_length_horizontal;
        public int log2_max_mv_length_vertical;
        public int max_bits_per_mb_denom;
        public int max_bytes_per_pic_denom;
        public int max_dec_frame_buffering;
        public boolean motion_vectors_over_pic_boundaries_flag;
        public int num_reorder_frames;

        public String toString() {
            return "BitstreamRestriction{motion_vectors_over_pic_boundaries_flag=" + this.motion_vectors_over_pic_boundaries_flag + ", max_bytes_per_pic_denom=" + this.max_bytes_per_pic_denom + ", max_bits_per_mb_denom=" + this.max_bits_per_mb_denom + ", log2_max_mv_length_horizontal=" + this.log2_max_mv_length_horizontal + ", log2_max_mv_length_vertical=" + this.log2_max_mv_length_vertical + ", num_reorder_frames=" + this.num_reorder_frames + ", max_dec_frame_buffering=" + this.max_dec_frame_buffering + '}';
        }
    }

    public String toString() {
        return "VUIParameters{\naspect_ratio_info_present_flag=" + this.aspect_ratio_info_present_flag + ShellAdbUtils.COMMAND_LINE_END + ", sar_width=" + this.sar_width + ShellAdbUtils.COMMAND_LINE_END + ", sar_height=" + this.sar_height + ShellAdbUtils.COMMAND_LINE_END + ", overscan_info_present_flag=" + this.overscan_info_present_flag + ShellAdbUtils.COMMAND_LINE_END + ", overscan_appropriate_flag=" + this.overscan_appropriate_flag + ShellAdbUtils.COMMAND_LINE_END + ", video_signal_type_present_flag=" + this.video_signal_type_present_flag + ShellAdbUtils.COMMAND_LINE_END + ", video_format=" + this.video_format + ShellAdbUtils.COMMAND_LINE_END + ", video_full_range_flag=" + this.video_full_range_flag + ShellAdbUtils.COMMAND_LINE_END + ", colour_description_present_flag=" + this.colour_description_present_flag + ShellAdbUtils.COMMAND_LINE_END + ", colour_primaries=" + this.colour_primaries + ShellAdbUtils.COMMAND_LINE_END + ", transfer_characteristics=" + this.transfer_characteristics + ShellAdbUtils.COMMAND_LINE_END + ", matrix_coefficients=" + this.matrix_coefficients + ShellAdbUtils.COMMAND_LINE_END + ", chroma_loc_info_present_flag=" + this.chroma_loc_info_present_flag + ShellAdbUtils.COMMAND_LINE_END + ", chroma_sample_loc_type_top_field=" + this.chroma_sample_loc_type_top_field + ShellAdbUtils.COMMAND_LINE_END + ", chroma_sample_loc_type_bottom_field=" + this.chroma_sample_loc_type_bottom_field + ShellAdbUtils.COMMAND_LINE_END + ", timing_info_present_flag=" + this.timing_info_present_flag + ShellAdbUtils.COMMAND_LINE_END + ", num_units_in_tick=" + this.num_units_in_tick + ShellAdbUtils.COMMAND_LINE_END + ", time_scale=" + this.time_scale + ShellAdbUtils.COMMAND_LINE_END + ", fixed_frame_rate_flag=" + this.fixed_frame_rate_flag + ShellAdbUtils.COMMAND_LINE_END + ", low_delay_hrd_flag=" + this.low_delay_hrd_flag + ShellAdbUtils.COMMAND_LINE_END + ", pic_struct_present_flag=" + this.pic_struct_present_flag + ShellAdbUtils.COMMAND_LINE_END + ", nalHRDParams=" + this.nalHRDParams + ShellAdbUtils.COMMAND_LINE_END + ", vclHRDParams=" + this.vclHRDParams + ShellAdbUtils.COMMAND_LINE_END + ", bitstreamRestriction=" + this.bitstreamRestriction + ShellAdbUtils.COMMAND_LINE_END + ", aspect_ratio=" + this.aspect_ratio + ShellAdbUtils.COMMAND_LINE_END + '}';
    }
}
