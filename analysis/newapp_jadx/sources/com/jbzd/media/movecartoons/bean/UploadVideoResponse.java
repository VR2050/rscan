package com.jbzd.media.movecartoons.bean;

/* loaded from: classes2.dex */
public class UploadVideoResponse {
    private DataBean data;
    private String status;
    private String time;

    public static class DataBean {
        private String file_duration;
        private String file_m3u8;
        private String file_name;
        private String file_preview_m3u8;
        private String file_quality;
        private String file_small_m3u8;
        private String file_small_preview_m3u8;
        private String file_small_quality;
        private String file_status;

        /* renamed from: id */
        private String f9926id;

        public String getFile_duration() {
            return this.file_duration;
        }

        public String getFile_m3u8() {
            return this.file_m3u8;
        }

        public String getFile_name() {
            return this.file_name;
        }

        public String getFile_preview_m3u8() {
            return this.file_preview_m3u8;
        }

        public String getFile_quality() {
            return this.file_quality;
        }

        public String getFile_small_m3u8() {
            return this.file_small_m3u8;
        }

        public String getFile_small_preview_m3u8() {
            return this.file_small_preview_m3u8;
        }

        public String getFile_small_quality() {
            return this.file_small_quality;
        }

        public String getFile_status() {
            return this.file_status;
        }

        public String getId() {
            return this.f9926id;
        }

        public void setFile_duration(String str) {
            this.file_duration = str;
        }

        public void setFile_m3u8(String str) {
            this.file_m3u8 = str;
        }

        public void setFile_name(String str) {
            this.file_name = str;
        }

        public void setFile_preview_m3u8(String str) {
            this.file_preview_m3u8 = str;
        }

        public void setFile_quality(String str) {
            this.file_quality = str;
        }

        public void setFile_small_m3u8(String str) {
            this.file_small_m3u8 = str;
        }

        public void setFile_small_preview_m3u8(String str) {
            this.file_small_preview_m3u8 = str;
        }

        public void setFile_small_quality(String str) {
            this.file_small_quality = str;
        }

        public void setFile_status(String str) {
            this.file_status = str;
        }

        public void setId(String str) {
            this.f9926id = str;
        }
    }

    public DataBean getData() {
        return this.data;
    }

    public String getStatus() {
        return this.status;
    }

    public String getTime() {
        return this.time;
    }

    public void setData(DataBean dataBean) {
        this.data = dataBean;
    }

    public void setStatus(String str) {
        this.status = str;
    }

    public void setTime(String str) {
        this.time = str;
    }
}
