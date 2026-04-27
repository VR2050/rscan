package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.util.AttributeSet;
import android.widget.LinearLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.hviews.MryTextView;

/* JADX INFO: loaded from: classes5.dex */
public class UserProfileShareDialogCell extends LinearLayout {
    private Object data;
    private BackupImageView ivArrvar;
    private MryTextView tvGroupNumber;
    private MryTextView tvName;

    public UserProfileShareDialogCell(Context context) {
        this(context, null);
    }

    public UserProfileShareDialogCell(Context context, Object data) {
        this(context, null, data);
    }

    public UserProfileShareDialogCell(Context context, AttributeSet attrs, Object data) {
        this(context, attrs, 0, data);
    }

    public UserProfileShareDialogCell(Context context, AttributeSet attrs, int defStyleAttr, Object data) {
        super(context, attrs, defStyleAttr);
        this.data = data;
        init(context);
    }

    private void init(Context context) {
        BackupImageView backupImageView = new BackupImageView(context);
        this.ivArrvar = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(7.5f));
        addView(this.ivArrvar, LayoutHelper.createFrame(45.0f, 45.0f, 16, 12.0f, 0.0f, 0.0f, 0.0f));
        MryTextView mryTextView = new MryTextView(context);
        this.tvName = mryTextView;
        mryTextView.setTextSize(14.0f);
        this.tvName.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        addView(this.tvName, LayoutHelper.createFrame(-1.0f, -2.0f, 16, 72.0f, 0.0f, 12.0f, 0.0f));
    }

    public void setData(Object data) {
        this.data = data;
    }
}
