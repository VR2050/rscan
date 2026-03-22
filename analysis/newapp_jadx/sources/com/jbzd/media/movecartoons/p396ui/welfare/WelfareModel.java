package com.jbzd.media.movecartoons.p396ui.welfare;

import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import java.io.Serializable;
import java.util.List;
import p005b.p199l.p258c.p259b0.InterfaceC2418b;

/* loaded from: classes2.dex */
public class WelfareModel implements Serializable {

    @InterfaceC2418b("avatar")
    private String avatar;

    @InterfaceC2418b("invite")
    private Integer invite;

    @InterfaceC2418b("isVip")
    private String isVip;

    @InterfaceC2418b("list")
    private List<TaskList> list;

    @InterfaceC2418b("nick")
    private String nick;

    @InterfaceC2418b("rank_type")
    private Integer rankType;

    @InterfaceC2418b("score")
    private Integer score;

    @InterfaceC2418b("watch")
    private Integer watch;

    public static class TaskList implements Serializable {

        @InterfaceC2418b("android_link")
        private String androidLink;

        @InterfaceC2418b("app_id")
        private Integer appId;

        @InterfaceC2418b("cover")
        private String cover;

        /* renamed from: id */
        @InterfaceC2418b("id")
        private Integer f10117id;

        @InterfaceC2418b("ios_link")
        private String iosLink;

        @InterfaceC2418b("is_daily_task")
        private Integer isDailyTask;

        @InterfaceC2418b("more_link")
        private String moreLink;

        @InterfaceC2418b("num")
        private Integer num;

        @InterfaceC2418b("score")
        private Integer score;

        @InterfaceC2418b("subtitle")
        private String subtitle;

        @InterfaceC2418b("task_receive_status")
        private Integer taskReceiveStatus;

        @InterfaceC2418b("task_status")
        private Integer taskStatus;

        @InterfaceC2418b(VideoListActivity.KEY_TITLE)
        private String title;

        @InterfaceC2418b("type")
        private Integer type;

        public String getAndroidLink() {
            return this.androidLink;
        }

        public Integer getAppId() {
            return this.appId;
        }

        public String getCover() {
            return this.cover;
        }

        public Integer getId() {
            return this.f10117id;
        }

        public String getIosLink() {
            return this.iosLink;
        }

        public Integer getIsDailyTask() {
            return this.isDailyTask;
        }

        public String getMoreLink() {
            return this.moreLink;
        }

        public Integer getNum() {
            return this.num;
        }

        public Integer getScore() {
            return this.score;
        }

        public String getSubtitle() {
            return this.subtitle;
        }

        public Integer getTaskReceiveStatus() {
            return this.taskReceiveStatus;
        }

        public Integer getTaskStatus() {
            return this.taskStatus;
        }

        public String getTitle() {
            return this.title;
        }

        public Integer getType() {
            return this.type;
        }

        public void setAndroidLink(String str) {
            this.androidLink = str;
        }

        public void setAppId(Integer num) {
            this.appId = num;
        }

        public void setCover(String str) {
            this.cover = str;
        }

        public void setId(Integer num) {
            this.f10117id = num;
        }

        public void setIosLink(String str) {
            this.iosLink = str;
        }

        public void setIsDailyTask(Integer num) {
            this.isDailyTask = num;
        }

        public void setMoreLink(String str) {
            this.moreLink = str;
        }

        public void setNum(Integer num) {
            this.num = num;
        }

        public void setScore(Integer num) {
            this.score = num;
        }

        public void setSubtitle(String str) {
            this.subtitle = str;
        }

        public void setTaskReceiveStatus(Integer num) {
            this.taskReceiveStatus = num;
        }

        public void setTaskStatus(Integer num) {
            this.taskStatus = num;
        }

        public void setTitle(String str) {
            this.title = str;
        }

        public void setType(Integer num) {
            this.type = num;
        }
    }

    public String getAvatar() {
        return this.avatar;
    }

    public Integer getInvite() {
        return this.invite;
    }

    public String getIsVip() {
        return this.isVip;
    }

    public List<TaskList> getList() {
        return this.list;
    }

    public String getNick() {
        return this.nick;
    }

    public Integer getRankType() {
        return this.rankType;
    }

    public Integer getScore() {
        return this.score;
    }

    public Integer getWatch() {
        return this.watch;
    }

    public void setAvatar(String str) {
        this.avatar = str;
    }

    public void setInvite(Integer num) {
        this.invite = num;
    }

    public void setIsVip(String str) {
        this.isVip = str;
    }

    public void setList(List<TaskList> list) {
        this.list = list;
    }

    public void setNick(String str) {
        this.nick = str;
    }

    public void setRankType(Integer num) {
        this.rankType = num;
    }

    public void setScore(Integer num) {
        this.score = num;
    }

    public void setWatch(Integer num) {
        this.watch = num;
    }
}
