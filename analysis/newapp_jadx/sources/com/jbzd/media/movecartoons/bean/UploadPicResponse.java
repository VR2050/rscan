package com.jbzd.media.movecartoons.bean;

/* loaded from: classes2.dex */
public class UploadPicResponse {
    private DataBean data;
    private String error;
    private String status;

    public static class DataBean {
        private String file;
        private String file_small;

        /* renamed from: id */
        private String f9925id;

        public String getFile() {
            return this.file;
        }

        public String getFile_small() {
            return this.file_small;
        }

        public String getId() {
            return this.f9925id;
        }

        public void setFile(String str) {
            this.file = str;
        }

        public void setFile_small(String str) {
            this.file_small = str;
        }

        public void setId(String str) {
            this.f9925id = str;
        }
    }

    public DataBean getData() {
        return this.data;
    }

    public String getError() {
        return this.error;
    }

    public String getStatus() {
        return this.status;
    }

    public void setData(DataBean dataBean) {
        this.data = dataBean;
    }

    public void setError(String str) {
        this.error = str;
    }

    public void setStatus(String str) {
        this.status = str;
    }
}
