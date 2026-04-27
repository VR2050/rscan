package com.bjz.comm.net.bean;

import android.os.Parcel;
import android.os.Parcelable;
import com.litesuits.orm.db.annotation.PrimaryKey;
import com.litesuits.orm.db.annotation.Table;
import com.litesuits.orm.db.enums.AssignType;
import java.io.Serializable;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes4.dex */
@Table("fc_list_reply")
public class FcReplyBean implements Parcelable, Serializable {
    public static final Parcelable.Creator<FcReplyBean> CREATOR = new Parcelable.Creator<FcReplyBean>() { // from class: com.bjz.comm.net.bean.FcReplyBean.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public FcReplyBean createFromParcel(Parcel in) {
            return new FcReplyBean(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public FcReplyBean[] newArray(int size) {
            return new FcReplyBean[size];
        }
    };
    private static final long serialVersionUID = -1340199269049097918L;

    @PrimaryKey(AssignType.BY_MYSELF)
    private long CommentID;
    private String Content;
    private int ContentType;
    private long CreateAt;
    private long CreateBy;
    private FcUserInfoBean Creator;
    private ArrayList<FCEntitysResponse> Entitys;
    private long ForumID;
    private long ForumUser;
    private boolean HasThumb;
    private ArrayList<FcMediaBean> Medias;
    private long ReplayID;
    private long ReplayUID;
    private FcUserInfoBean ReplayUser;
    private int Status;
    private ArrayList<FcReplyBean> SubComment;
    private int SubComments;
    private long SupID;
    private long SupUser;
    private int ThumbUp;

    public FcReplyBean() {
        this.Medias = new ArrayList<>();
        this.Entitys = new ArrayList<>();
        this.SubComment = new ArrayList<>();
    }

    public FcReplyBean(long forumID, long forumUser, long commentID, long supID, long supUser, long replayID, long replayUID) {
        this.Medias = new ArrayList<>();
        this.Entitys = new ArrayList<>();
        this.SubComment = new ArrayList<>();
        this.ForumID = forumID;
        this.ForumUser = forumUser;
        this.CommentID = commentID;
        this.SupID = supID;
        this.SupUser = supUser;
        this.ReplayID = replayID;
        this.ReplayUID = replayUID;
    }

    public FcReplyBean(String content, int contentType, long forumID, long forumUser, long commentID, long supID, long supUser, long replayID, long replayUID, long createBy, long createAt, int status, int subComments, boolean hasThumb, int thumbUp, ArrayList<FcMediaBean> medias, ArrayList<FCEntitysResponse> entitys, FcUserInfoBean replayUser, FcUserInfoBean creator, ArrayList<FcReplyBean> SubComment) {
        this.Medias = new ArrayList<>();
        this.Entitys = new ArrayList<>();
        this.SubComment = new ArrayList<>();
        this.Content = content;
        this.ContentType = contentType;
        this.ForumID = forumID;
        this.ForumUser = forumUser;
        this.CommentID = commentID;
        this.SupID = supID;
        this.SupUser = supUser;
        this.ReplayID = replayID;
        this.ReplayUID = replayUID;
        this.CreateBy = createBy;
        this.CreateAt = createAt;
        this.Status = status;
        this.SubComments = subComments;
        this.HasThumb = hasThumb;
        this.ThumbUp = thumbUp;
        this.Medias = medias;
        this.Entitys = entitys;
        this.ReplayUser = replayUser;
        this.Creator = creator;
        this.SubComment = SubComment;
    }

    protected FcReplyBean(Parcel in) {
        this.Medias = new ArrayList<>();
        this.Entitys = new ArrayList<>();
        this.SubComment = new ArrayList<>();
        this.CommentID = in.readLong();
        this.Content = in.readString();
        this.ContentType = in.readInt();
        this.ForumID = in.readLong();
        this.ForumUser = in.readLong();
        this.SupID = in.readLong();
        this.SupUser = in.readLong();
        this.ReplayID = in.readLong();
        this.ReplayUID = in.readLong();
        this.CreateBy = in.readLong();
        this.CreateAt = in.readLong();
        this.Status = in.readInt();
        this.SubComments = in.readInt();
        this.HasThumb = in.readByte() != 0;
        this.ThumbUp = in.readInt();
        this.ReplayUser = (FcUserInfoBean) in.readParcelable(FcUserInfoBean.class.getClassLoader());
        this.Creator = (FcUserInfoBean) in.readParcelable(FcUserInfoBean.class.getClassLoader());
        this.SubComment = in.createTypedArrayList(CREATOR);
    }

    public long getForumID() {
        return this.ForumID;
    }

    public void setForumID(long forumID) {
        this.ForumID = forumID;
    }

    public long getCommentID() {
        return this.CommentID;
    }

    public void setCommentID(long commentID) {
        this.CommentID = commentID;
    }

    public String getContent() {
        return this.Content;
    }

    public void setContent(String content) {
        this.Content = content;
    }

    public int getContentType() {
        return this.ContentType;
    }

    public void setContentType(int contentType) {
        this.ContentType = contentType;
    }

    public long getCreateAt() {
        return this.CreateAt;
    }

    public void setCreateAt(long createAt) {
        this.CreateAt = createAt;
    }

    public long getForumUser() {
        return this.ForumUser;
    }

    public void setForumUser(long forumUser) {
        this.ForumUser = forumUser;
    }

    public long getCreateBy() {
        return this.CreateBy;
    }

    public void setCreateBy(long createBy) {
        this.CreateBy = createBy;
    }

    public long getReplayID() {
        return this.ReplayID;
    }

    public void setReplayID(long replayID) {
        this.ReplayID = replayID;
    }

    public long getReplayUID() {
        return this.ReplayUID;
    }

    public void setReplayUID(long replayUID) {
        this.ReplayUID = replayUID;
    }

    public long getSupID() {
        return this.SupID;
    }

    public void setSupID(long supID) {
        this.SupID = supID;
    }

    public long getSupUser() {
        return this.SupUser;
    }

    public void setSupUser(long supUser) {
        this.SupUser = supUser;
    }

    public int getStatus() {
        return this.Status;
    }

    public void setStatus(int status) {
        this.Status = status;
    }

    public int getSubComments() {
        return this.SubComments;
    }

    public void setSubComments(int subComments) {
        this.SubComments = subComments;
    }

    public boolean isHasThumb() {
        return this.HasThumb;
    }

    public void setHasThumb(boolean hasThumb) {
        this.HasThumb = hasThumb;
    }

    public int getThumbUp() {
        return this.ThumbUp;
    }

    public void setThumbUp(int thumbUp) {
        this.ThumbUp = thumbUp;
    }

    public ArrayList<FcMediaBean> getMedias() {
        return this.Medias;
    }

    public void setMedias(ArrayList<FcMediaBean> medias) {
        this.Medias = medias;
    }

    public ArrayList<FCEntitysResponse> getEntitys() {
        return this.Entitys;
    }

    public void setEntitys(ArrayList<FCEntitysResponse> entitys) {
        this.Entitys = entitys;
    }

    public FcUserInfoBean getCreator() {
        return this.Creator;
    }

    public void setCreator(FcUserInfoBean creator) {
        this.Creator = creator;
    }

    public FcUserInfoBean getReplayUser() {
        return this.ReplayUser;
    }

    public void setReplayUser(FcUserInfoBean replayUser) {
        this.ReplayUser = replayUser;
    }

    public ArrayList<FcReplyBean> getSubComment() {
        return this.SubComment;
    }

    public void setSubComment(ArrayList<FcReplyBean> subComment) {
        this.SubComment = subComment;
    }

    public String toString() {
        return "FcReplyBean{ForumID=" + this.ForumID + ", CommentID=" + this.CommentID + ", Content='" + this.Content + "', ContentType=" + this.ContentType + ", CreateAt=" + this.CreateAt + ", ForumUser=" + this.ForumUser + ", CreateBy=" + this.CreateBy + ", ReplayID=" + this.ReplayID + ", ReplayUID=" + this.ReplayUID + ", SupID=" + this.SupID + ", SupUser=" + this.SupUser + ", Status=" + this.Status + ", SubComments=" + this.SubComments + ", HasThumb=" + this.HasThumb + ", ThumbUp=" + this.ThumbUp + ", Medias=" + this.Medias + ", Entitys=" + this.Entitys + ", Creator=" + this.Creator + ", ReplayUser=" + this.ReplayUser + ", childFcReplyBean=" + this.SubComment + '}';
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeLong(this.CommentID);
        parcel.writeString(this.Content);
        parcel.writeInt(this.ContentType);
        parcel.writeLong(this.ForumID);
        parcel.writeLong(this.ForumUser);
        parcel.writeLong(this.SupID);
        parcel.writeLong(this.SupUser);
        parcel.writeLong(this.ReplayID);
        parcel.writeLong(this.ReplayUID);
        parcel.writeLong(this.CreateBy);
        parcel.writeLong(this.CreateAt);
        parcel.writeInt(this.Status);
        parcel.writeInt(this.SubComments);
        parcel.writeByte(this.HasThumb ? (byte) 1 : (byte) 0);
        parcel.writeInt(this.ThumbUp);
        parcel.writeParcelable(this.ReplayUser, i);
        parcel.writeParcelable(this.Creator, i);
        parcel.writeTypedList(this.SubComment);
    }
}
