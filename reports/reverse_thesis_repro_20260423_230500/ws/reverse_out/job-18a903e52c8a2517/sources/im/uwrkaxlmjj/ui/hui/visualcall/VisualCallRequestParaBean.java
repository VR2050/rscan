package im.uwrkaxlmjj.ui.hui.visualcall;

import com.litesuits.orm.db.annotation.PrimaryKey;
import com.litesuits.orm.db.annotation.Table;
import com.litesuits.orm.db.enums.AssignType;
import java.io.Serializable;

/* JADX INFO: loaded from: classes5.dex */
@Table("visualcall_para")
public class VisualCallRequestParaBean implements Serializable {
    private int admin_id;
    private String app_id;
    private String gslb;

    @PrimaryKey(AssignType.AUTO_INCREMENT)
    private int id;
    private String json;
    private String strId;
    private String token;
    private boolean video;

    public boolean isVideo() {
        return this.video;
    }

    public void setVideo(boolean video) {
        this.video = video;
    }

    public String getStrId() {
        return this.strId;
    }

    public void setStrId(String strId) {
        this.strId = strId;
    }

    public int getAdmin_id() {
        return this.admin_id;
    }

    public void setAdmin_id(int admin_id) {
        this.admin_id = admin_id;
    }

    public String getApp_id() {
        return this.app_id;
    }

    public void setApp_id(String app_id) {
        this.app_id = app_id;
    }

    public String getToken() {
        return this.token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getGslb() {
        return this.gslb;
    }

    public void setGslb(String gslb) {
        this.gslb = gslb;
    }

    public String getJson() {
        return this.json;
    }

    public void setJson(String json) {
        this.json = json;
    }

    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
    }
}
