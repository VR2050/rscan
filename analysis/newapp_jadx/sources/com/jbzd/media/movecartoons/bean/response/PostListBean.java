package com.jbzd.media.movecartoons.bean.response;

import androidx.annotation.NonNull;
import com.jbzd.media.movecartoons.bean.response.PostDetailBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import p005b.p006a.p007a.p008a.p009a.C0843e0;

/* loaded from: classes2.dex */
public class PostListBean implements Serializable {
    public String can_view;
    public List<TagBean> categories;
    public String city;
    public String click;
    public String comment;
    public String content;
    public String deny_msg;
    public String favorite;
    public List<PostDetailBean.FilesBean> files;
    public String has_love;

    /* renamed from: id */
    public String f9980id;
    public String is_hot;
    public String is_own;
    public String is_top;
    public String love;
    public String money;
    public String pay_type;
    public String position;
    public String province;
    public int realPage = 1;
    public String status;
    public String status_text;
    public String time;
    public String title;
    public String type;
    public UserBean user;

    public static class CategoriesBean implements Serializable, Cloneable {

        /* renamed from: id */
        public String f9981id;
        public String name;

        @NonNull
        public Object clone() {
            return super.clone();
        }

        public String getId() {
            return this.f9981id;
        }

        public String getName() {
            return this.name;
        }

        public void setId(String str) {
            this.f9981id = str;
        }

        public void setName(String str) {
            this.name = str;
        }
    }

    public static class UserBean {

        /* renamed from: id */
        public String f9982id;
        public String img;
        public String is_follow;
        public String is_up;
        public String is_vip;
        public String nickname;
        public String sex;

        public String getId() {
            return this.f9982id;
        }

        public String getImg() {
            return this.img;
        }

        public String getIs_follow() {
            return this.is_follow;
        }

        public String getIs_up() {
            return this.is_up;
        }

        public String getIs_vip() {
            return this.is_vip;
        }

        public String getNickname() {
            return this.nickname;
        }

        public String getSex() {
            return this.sex;
        }

        public boolean isFollow() {
            return "y".equals(this.is_follow);
        }

        public boolean isUp() {
            return "y".equals(this.is_up);
        }

        public boolean isVip() {
            return Objects.equals(this.is_vip, "y");
        }

        public void setId(String str) {
            this.f9982id = str;
        }

        public void setImg(String str) {
            this.img = str;
        }

        public void setIs_follow(String str) {
            this.is_follow = str;
        }

        public void setIs_up(String str) {
            this.is_up = str;
        }

        public void setIs_vip(String str) {
            this.is_vip = str;
        }

        public void setNickname(String str) {
            this.nickname = str;
        }

        public void setSex(String str) {
            this.sex = str;
        }
    }

    public String getCan_view() {
        return this.can_view;
    }

    public List<TagBean> getCategories() {
        return this.categories;
    }

    public String getCity() {
        return this.city;
    }

    public String getClick() {
        return this.click;
    }

    public String getComment() {
        return this.comment.equals("0") ? "评论" : C0843e0.m182a(this.comment);
    }

    public String getContent() {
        return this.content;
    }

    public String getDeny_msg() {
        return this.deny_msg;
    }

    public String getFavorite() {
        return this.favorite;
    }

    public List<PostDetailBean.FilesBean> getFiles() {
        return this.files;
    }

    public String getHas_love() {
        return this.has_love;
    }

    public String getId() {
        return this.f9980id;
    }

    public String getIs_hot() {
        return this.is_hot;
    }

    public String getIs_own() {
        return this.is_own;
    }

    public String getIs_top() {
        return this.is_top;
    }

    public String getLove() {
        return this.love.equals("0") ? "点赞" : C0843e0.m182a(this.love);
    }

    public String getMoney() {
        return this.money;
    }

    public String getPay_type() {
        return this.pay_type;
    }

    public String getPosition() {
        return this.position;
    }

    public String getProvince() {
        return this.province;
    }

    public String getStatus() {
        return this.status;
    }

    public String getStatus_text() {
        return this.status_text;
    }

    public String getTime() {
        return this.time;
    }

    public String getTitle() {
        return this.title;
    }

    public String getType() {
        return this.type;
    }

    public UserBean getUser() {
        return this.user;
    }

    public void setCan_view(String str) {
        this.can_view = str;
    }

    public void setCategories(List<TagBean> list) {
        this.categories = list;
    }

    public void setCity(String str) {
        this.city = str;
    }

    public void setClick(String str) {
        this.click = str;
    }

    public void setComment(String str) {
        this.comment = str;
    }

    public void setContent(String str) {
        this.content = str;
    }

    public void setDeny_msg(String str) {
        this.deny_msg = str;
    }

    public void setFavorite(String str) {
        this.favorite = str;
    }

    public void setFiles(List<PostDetailBean.FilesBean> list) {
        this.files = list;
    }

    public void setHas_love(String str) {
        this.has_love = str;
    }

    public void setId(String str) {
        this.f9980id = str;
    }

    public void setIs_hot(String str) {
        this.is_hot = str;
    }

    public void setIs_own(String str) {
        this.is_own = str;
    }

    public void setIs_top(String str) {
        this.is_top = str;
    }

    public void setLove(String str) {
        this.love = str;
    }

    public void setMoney(String str) {
        this.money = str;
    }

    public void setPay_type(String str) {
        this.pay_type = str;
    }

    public void setPosition(String str) {
        this.position = str;
    }

    public void setProvince(String str) {
        this.province = str;
    }

    public void setStatus(String str) {
        this.status = str;
    }

    public void setStatus_text(String str) {
        this.status_text = str;
    }

    public void setTime(String str) {
        this.time = str;
    }

    public void setTitle(String str) {
        this.title = str;
    }

    public void setType(String str) {
        this.type = str;
    }

    public void setUser(UserBean userBean) {
        this.user = userBean;
    }
}
