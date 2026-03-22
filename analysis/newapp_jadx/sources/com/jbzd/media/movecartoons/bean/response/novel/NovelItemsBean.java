package com.jbzd.media.movecartoons.bean.response.novel;

import com.jbzd.media.movecartoons.bean.response.comicsinfo.Tags;
import java.io.Serializable;
import java.util.List;

/* loaded from: classes2.dex */
public class NovelItemsBean implements Serializable, Cloneable {
    private String alias_name;
    private String author;
    private String category;
    private String category_name;
    private String chapter_count;
    private String click;
    private String comment;
    private String description;
    private String favorite;
    private String free_chapter;
    private String ico;

    /* renamed from: id */
    private String f10029id;
    private String img;
    private String img_x;
    private String is_adult;
    private String money;
    private String name;
    private String pay_type;
    private String status;
    private String status_text;
    private String sub_title;
    private List<Tags> tags;
    private String type;
    private String update_date;
    private String update_status;
    public boolean isSelect = false;
    public String link = "";

    public String getAlias_name() {
        return this.alias_name;
    }

    public String getAuthor() {
        return this.author;
    }

    public String getCategory() {
        return this.category;
    }

    public String getCategory_name() {
        return this.category_name;
    }

    public String getChapter_count() {
        return this.chapter_count;
    }

    public String getClick() {
        return this.click;
    }

    public String getComment() {
        return this.comment;
    }

    public String getDescription() {
        return this.description;
    }

    public String getFavorite() {
        return this.favorite;
    }

    public String getFree_chapter() {
        return this.free_chapter;
    }

    public String getIco() {
        return this.ico;
    }

    public String getId() {
        return this.f10029id;
    }

    public String getImg() {
        return this.img;
    }

    public String getImg_x() {
        return this.img_x;
    }

    public String getIs_adult() {
        return this.is_adult;
    }

    public String getMoney() {
        return this.money;
    }

    public String getName() {
        return this.name;
    }

    public String getPay_type() {
        return this.pay_type;
    }

    public String getStatus() {
        return this.status;
    }

    public String getStatus_text() {
        return this.status_text;
    }

    public String getSub_title() {
        return this.sub_title;
    }

    public List<Tags> getTags() {
        return this.tags;
    }

    public String getType() {
        return this.type;
    }

    public String getUpdate_date() {
        return this.update_date;
    }

    public String getUpdate_status() {
        return this.update_status;
    }

    public void setAlias_name(String str) {
        this.alias_name = str;
    }

    public void setAuthor(String str) {
        this.author = str;
    }

    public void setCategory(String str) {
        this.category = str;
    }

    public void setCategory_name(String str) {
        this.category_name = str;
    }

    public void setChapter_count(String str) {
        this.chapter_count = str;
    }

    public void setClick(String str) {
        this.click = str;
    }

    public void setComment(String str) {
        this.comment = str;
    }

    public void setDescription(String str) {
        this.description = str;
    }

    public void setFavorite(String str) {
        this.favorite = str;
    }

    public void setFree_chapter(String str) {
        this.free_chapter = str;
    }

    public void setIco(String str) {
        this.ico = str;
    }

    public void setId(String str) {
        this.f10029id = str;
    }

    public void setImg(String str) {
        this.img = str;
    }

    public void setImg_x(String str) {
        this.img_x = str;
    }

    public void setIs_adult(String str) {
        this.is_adult = str;
    }

    public void setMoney(String str) {
        this.money = str;
    }

    public void setName(String str) {
        this.name = str;
    }

    public void setPay_type(String str) {
        this.pay_type = str;
    }

    public void setStatus(String str) {
        this.status = str;
    }

    public void setStatus_text(String str) {
        this.status_text = str;
    }

    public void setSub_title(String str) {
        this.sub_title = str;
    }

    public void setTags(List<Tags> list) {
        this.tags = list;
    }

    public void setType(String str) {
        this.type = str;
    }

    public void setUpdate_date(String str) {
        this.update_date = str;
    }

    public void setUpdate_status(String str) {
        this.update_status = str;
    }
}
