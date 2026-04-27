package im.uwrkaxlmjj.javaBean.fc;

import android.os.Parcel;
import android.os.Parcelable;
import com.bjz.comm.net.bean.FcEntitysBean;
import com.bjz.comm.net.bean.RespTopicBean;
import im.uwrkaxlmjj.messenger.MediaController;
import java.util.ArrayList;
import java.util.HashMap;

/* JADX INFO: loaded from: classes2.dex */
public class PublishFcBean implements Parcelable {
    public static final Parcelable.Creator<PublishFcBean> CREATOR = new Parcelable.Creator<PublishFcBean>() { // from class: im.uwrkaxlmjj.javaBean.fc.PublishFcBean.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public PublishFcBean createFromParcel(Parcel in) {
            return new PublishFcBean(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public PublishFcBean[] newArray(int size) {
            return new PublishFcBean[size];
        }
    };
    private String Content;
    private int ContentType;
    private ArrayList<FcEntitysBean> Entitys = new ArrayList<>();
    private int Permission;
    private HashMap<String, RespTopicBean.Item> Topic;
    private int currentSelectMediaType;
    private long id;
    private HashMap<Integer, MediaController.PhotoEntry> selectedPhotos;
    private ArrayList<Integer> selectedPhotosOrder;

    public PublishFcBean() {
    }

    protected PublishFcBean(Parcel in) {
        this.id = in.readLong();
        this.ContentType = in.readInt();
        this.Content = in.readString();
        this.Permission = in.readInt();
        this.currentSelectMediaType = in.readInt();
    }

    public int getContentType() {
        return this.ContentType;
    }

    public void setContentType(int contentType) {
        this.ContentType = contentType;
    }

    public String getContent() {
        return this.Content;
    }

    public void setContent(String content) {
        this.Content = content;
    }

    public int getPermission() {
        return this.Permission;
    }

    public void setPermission(int permission) {
        this.Permission = permission;
    }

    public HashMap<String, RespTopicBean.Item> getTopic() {
        return this.Topic;
    }

    public void setTopic(HashMap<String, RespTopicBean.Item> topic) {
        this.Topic = topic;
    }

    public HashMap<Integer, MediaController.PhotoEntry> getSelectedPhotos() {
        return this.selectedPhotos;
    }

    public void setSelectedPhotos(HashMap<Integer, MediaController.PhotoEntry> selectedPhotos) {
        this.selectedPhotos = selectedPhotos;
    }

    public ArrayList<Integer> getSelectedPhotosOrder() {
        return this.selectedPhotosOrder;
    }

    public void setSelectedPhotosOrder(ArrayList<Integer> selectedPhotosOrder) {
        this.selectedPhotosOrder = selectedPhotosOrder;
    }

    public int getCurrentSelectMediaType() {
        return this.currentSelectMediaType;
    }

    public void setCurrentSelectMediaType(int currentSelectMediaType) {
        this.currentSelectMediaType = currentSelectMediaType;
    }

    public ArrayList<FcEntitysBean> getEntitys() {
        return this.Entitys;
    }

    public void setEntitys(ArrayList<FcEntitysBean> entitys) {
        this.Entitys = entitys;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(this.id);
        dest.writeInt(this.ContentType);
        dest.writeString(this.Content);
        dest.writeInt(this.Permission);
        dest.writeInt(this.currentSelectMediaType);
    }
}
