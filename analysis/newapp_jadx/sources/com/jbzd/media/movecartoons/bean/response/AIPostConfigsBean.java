package com.jbzd.media.movecartoons.bean.response;

import java.io.Serializable;
import java.util.List;

/* loaded from: classes2.dex */
public class AIPostConfigsBean implements Serializable {
    public String ai_change_cat_id;
    public String ai_change_min_face_num;
    public String ai_change_min_num;
    public String ai_change_price;
    public String ai_change_video_min_face_num;
    public String ai_change_video_price;
    public List<AiChangeVideoTemplateBean> ai_change_video_template;
    public String ai_huihua_cat_id;
    public String ai_huihua_max_num;
    public String ai_huihua_price;
    public String ai_quyi_cat_id;
    public String ai_quyi_max_num;
    public String ai_quyi_price;
    public String ai_tips;

    public static class AiChangeVideoTemplateBean {
        public String image_url;
        public String image_value;
        public String video_url;
        public String video_value;

        public String getImage_url() {
            return this.image_url;
        }

        public String getImage_value() {
            return this.image_value;
        }

        public String getVideo_url() {
            return this.video_url;
        }

        public String getVideo_value() {
            return this.video_value;
        }

        public void setImage_url(String str) {
            this.image_url = str;
        }

        public void setImage_value(String str) {
            this.image_value = str;
        }

        public void setVideo_url(String str) {
            this.video_url = str;
        }

        public void setVideo_value(String str) {
            this.video_value = str;
        }
    }

    public String getAi_change_cat_id() {
        return this.ai_change_cat_id;
    }

    public String getAi_change_min_face_num() {
        return this.ai_change_min_face_num;
    }

    public String getAi_change_min_num() {
        return this.ai_change_min_num;
    }

    public String getAi_change_price() {
        return this.ai_change_price;
    }

    public String getAi_change_video_min_face_num() {
        return this.ai_change_video_min_face_num;
    }

    public String getAi_change_video_price() {
        return this.ai_change_video_price;
    }

    public List<AiChangeVideoTemplateBean> getAi_change_video_template() {
        return this.ai_change_video_template;
    }

    public String getAi_huihua_cat_id() {
        return this.ai_huihua_cat_id;
    }

    public String getAi_huihua_max_num() {
        return this.ai_huihua_max_num;
    }

    public String getAi_huihua_price() {
        return this.ai_huihua_price;
    }

    public String getAi_quyi_cat_id() {
        return this.ai_quyi_cat_id;
    }

    public String getAi_quyi_max_num() {
        return this.ai_quyi_max_num;
    }

    public String getAi_quyi_price() {
        return this.ai_quyi_price;
    }

    public String getAi_tips() {
        return this.ai_tips;
    }

    public void setAi_change_cat_id(String str) {
        this.ai_change_cat_id = str;
    }

    public void setAi_change_min_face_num(String str) {
        this.ai_change_min_face_num = str;
    }

    public void setAi_change_min_num(String str) {
        this.ai_change_min_num = str;
    }

    public void setAi_change_price(String str) {
        this.ai_change_price = str;
    }

    public void setAi_change_video_min_face_num(String str) {
        this.ai_change_video_min_face_num = str;
    }

    public void setAi_change_video_price(String str) {
        this.ai_change_video_price = str;
    }

    public void setAi_change_video_template(List<AiChangeVideoTemplateBean> list) {
        this.ai_change_video_template = list;
    }

    public void setAi_huihua_cat_id(String str) {
        this.ai_huihua_cat_id = str;
    }

    public void setAi_huihua_max_num(String str) {
        this.ai_huihua_max_num = str;
    }

    public void setAi_huihua_price(String str) {
        this.ai_huihua_price = str;
    }

    public void setAi_quyi_cat_id(String str) {
        this.ai_quyi_cat_id = str;
    }

    public void setAi_quyi_max_num(String str) {
        this.ai_quyi_max_num = str;
    }

    public void setAi_quyi_price(String str) {
        this.ai_quyi_price = str;
    }

    public void setAi_tips(String str) {
        this.ai_tips = str;
    }
}
