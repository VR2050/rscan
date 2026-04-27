package im.uwrkaxlmjj.ui.hui.visualcall;

import com.litesuits.orm.db.annotation.PrimaryKey;
import com.litesuits.orm.db.annotation.Table;
import com.litesuits.orm.db.enums.AssignType;
import java.io.Serializable;

/* JADX INFO: loaded from: classes5.dex */
@Table("visualcall_request")
public class VisualCallRequestBean implements Serializable {

    @PrimaryKey(AssignType.BY_MYSELF)
    private String strId;
    private long timestamp;

    public String getStrId() {
        return this.strId;
    }

    public void setStrId(String strId) {
        this.strId = strId;
    }

    public long getTimestamp() {
        return this.timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }
}
