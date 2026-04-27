package im.uwrkaxlmjj.ui.hcells;

import android.content.Context;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AvatarDelCell extends FrameLayout {
    private AvatarDrawable avatarDrawable;
    private BackupImageView avatarImage;
    private AvatarDelDelegate delegate;
    private ImageView ivDelete;
    private TextView tvName;

    public interface AvatarDelDelegate {
        void onClickDelete();
    }

    public void setDelegate(AvatarDelDelegate delegate) {
        this.delegate = delegate;
    }

    public AvatarDelCell(Context context) {
        this(context, null);
    }

    public AvatarDelCell(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public AvatarDelCell(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        initLayout(context);
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(65.0f), 1073741824));
    }

    private void initLayout(Context context) {
        FrameLayout container = new FrameLayout(context);
        addView(container, LayoutHelper.createFrame(-2, -2, 1));
        AvatarDrawable avatarDrawable = new AvatarDrawable();
        this.avatarDrawable = avatarDrawable;
        avatarDrawable.setTextSize(AndroidUtilities.dp(16.0f));
        BackupImageView backupImageView = new BackupImageView(context);
        this.avatarImage = backupImageView;
        backupImageView.setRoundRadius(AndroidUtilities.dp(7.5f));
        container.addView(this.avatarImage, LayoutHelper.createFrame(45, 45, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(8.0f)));
        TextView textView = new TextView(context);
        this.tvName = textView;
        textView.setTextColor(Theme.getColor(Theme.key_chats_menuItemText));
        this.tvName.setTextSize(1, 15.0f);
        this.tvName.setLines(1);
        this.tvName.setMaxLines(1);
        this.tvName.setSingleLine(true);
        this.tvName.setGravity(19);
        this.tvName.setEllipsize(TextUtils.TruncateAt.END);
        ImageView imageView = new ImageView(context);
        this.ivDelete = imageView;
        imageView.setImageResource(R.id.icon_create_group_delete);
        this.ivDelete.setPadding(AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(8.0f));
        container.addView(this.ivDelete, LayoutHelper.createFrame(32.0f, 32.0f, 5, 0.0f, AndroidUtilities.dp(-2.0f), AndroidUtilities.dp(-2.0f), 0.0f));
        this.ivDelete.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hcells.-$$Lambda$AvatarDelCell$TlAXsm6M4U_JaZXyu2RdSm4CX4M
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initLayout$0$AvatarDelCell(view);
            }
        });
        setWillNotDraw(false);
    }

    public /* synthetic */ void lambda$initLayout$0$AvatarDelCell(View v) {
        AvatarDelDelegate avatarDelDelegate = this.delegate;
        if (avatarDelDelegate != null) {
            avatarDelDelegate.onClickDelete();
        }
    }

    public void setUser(TLRPC.User user) {
        if (user == null) {
            return;
        }
        this.avatarDrawable.setInfo(user);
        this.tvName.setText(ContactsController.formatName(user.first_name, user.last_name));
        this.avatarImage.setImage(ImageLocation.getForUser(user, false), "50_50", this.avatarDrawable, user);
    }
}
