package im.uwrkaxlmjj.javaBean.fc;

import java.io.Serializable;

/* JADX INFO: loaded from: classes2.dex */
public class AllMsgBean implements Serializable {
    private String Content;
    private int ContentType;
    private long ForumID;
    private long OwenerID;
    private long PostTime;
    private long ReplyFromID;
    private long ReplyToForumID;
    private long ReplyToID;
    private long SourceForumID;
    private String fcContent;
    private long fcForumID;
    private String fcPath;

    public AllMsgBean(long fcForumID, long forumID, String content, long postTime, int contentType, long sourceForumID, long replyToForumID, long owenerID, long replyFromID, long replyToID, long likeUserID) {
        this.fcForumID = fcForumID;
        this.ForumID = forumID;
        this.Content = content;
        this.PostTime = postTime;
        this.ContentType = contentType;
        this.SourceForumID = sourceForumID;
        this.ReplyToForumID = replyToForumID;
        this.OwenerID = owenerID;
        this.ReplyFromID = replyFromID;
        this.ReplyToID = replyToID;
    }

    public long getFcForumID() {
        return this.fcForumID;
    }

    public void setFcForumID(long fcForumID) {
        this.fcForumID = fcForumID;
    }

    public String getFcContent() {
        return this.fcContent;
    }

    public void setFcContent(String fcContent) {
        this.fcContent = fcContent;
    }

    public long getForumID() {
        return this.ForumID;
    }

    public void setForumID(long forumID) {
        this.ForumID = forumID;
    }

    public String getContent() {
        return this.Content;
    }

    public void setContent(String content) {
        this.Content = content;
    }

    public long getPostTime() {
        return this.PostTime;
    }

    public void setPostTime(long postTime) {
        this.PostTime = postTime;
    }

    public int getContentType() {
        return this.ContentType;
    }

    public void setContentType(int contentType) {
        this.ContentType = contentType;
    }

    public long getSourceForumID() {
        return this.SourceForumID;
    }

    public void setSourceForumID(long sourceForumID) {
        this.SourceForumID = sourceForumID;
    }

    public long getReplyToForumID() {
        return this.ReplyToForumID;
    }

    public void setReplyToForumID(long replyToForumID) {
        this.ReplyToForumID = replyToForumID;
    }

    public long getOwenerID() {
        return this.OwenerID;
    }

    public void setOwenerID(long owenerID) {
        this.OwenerID = owenerID;
    }

    public long getReplyFromID() {
        return this.ReplyFromID;
    }

    public void setReplyFromID(long replyFromID) {
        this.ReplyFromID = replyFromID;
    }

    public long getReplyToID() {
        return this.ReplyToID;
    }

    public void setReplyToID(long replyToID) {
        this.ReplyToID = replyToID;
    }

    public String getFcPath() {
        return this.fcPath;
    }

    public void setFcPath(String fcPath) {
        this.fcPath = fcPath;
    }
}
