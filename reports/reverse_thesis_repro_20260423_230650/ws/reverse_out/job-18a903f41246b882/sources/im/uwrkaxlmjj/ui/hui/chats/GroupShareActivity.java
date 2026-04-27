package im.uwrkaxlmjj.ui.hui.chats;

import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Environment;
import android.text.TextUtils;
import android.util.Base64;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import com.king.zxing.util.CodeUtils;
import com.litesuits.orm.db.assit.SQLBuilder;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryImageView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class GroupShareActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private BackupImageView bivGroupAvatar;
    private ViewTreeObserver.OnGlobalLayoutListener changeNameWidthListener = new ViewTreeObserver.OnGlobalLayoutListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.GroupShareActivity.1
        @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
        public void onGlobalLayout() {
            CharSequence nt;
            int allw = GroupShareActivity.this.tvGroupNameParent.getMeasuredWidth();
            if (allw > 0 && (nt = GroupShareActivity.this.tvGroupNumber.getText()) != null) {
                float nw = GroupShareActivity.this.tvGroupNumber.getPaint().measureText(nt.toString(), 0, nt.toString().length());
                if (nw > 0.0f) {
                    int plusw = GroupShareActivity.this.tvGroupName.getMeasuredWidth() + ((int) nw);
                    if (plusw > allw) {
                        GroupShareActivity.this.tvGroupNameParent.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                        ViewGroup.LayoutParams lpName = GroupShareActivity.this.tvGroupName.getLayoutParams();
                        lpName.width = (allw - ((int) nw)) - AndroidUtilities.dp(5.0f);
                        GroupShareActivity.this.tvGroupName.setLayoutParams(lpName);
                    }
                }
            }
        }
    };
    private TLRPC.Chat chat;
    private TLRPC.ChatFull chatInfo;
    private ImageView ivGroupQrCode;
    private MryImageView ivQrCode;
    private LinearLayout llContainer;
    private Context mContext;
    private ProgressBar progressBar;
    private String ret;
    private RelativeLayout rlContainer;
    private MryTextView tvGroupMembers;
    private MryTextView tvGroupName;
    private View tvGroupNameParent;
    private MryTextView tvGroupNumber;
    private MryTextView tvSave;
    private MryTextView tvShareQrCode;
    private TLRPC.User user;

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean onTouch(View v, MotionEvent event) {
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.chatInfoDidLoad);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        if (this.fragmentView != null) {
            this.fragmentView.getViewTreeObserver().removeOnGlobalLayoutListener(this.changeNameWidthListener);
        }
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.chatInfoDidLoad);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.actionBar.setAddToContainer(false);
        this.fragmentView = View.inflate(context, R.layout.activity_group_share_layout, null);
        this.fragmentView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$GroupShareActivity$bw8rQ-YhcjONsXW4mVc0BV0QBg8
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return GroupShareActivity.onTouch(view, motionEvent);
            }
        });
        this.fragmentView.setBackground(new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, new int[]{Color.parseColor("#449FFD"), Color.parseColor("#45CAFA")}));
        initActionbar();
        initCodeContainer();
        createQRCode();
        return this.fragmentView;
    }

    private void initActionbar() {
        FrameLayout flTitleBarContainer = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_title_bar_container);
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) flTitleBarContainer.getLayoutParams();
        layoutParams.height = ActionBar.getCurrentActionBarHeight() + AndroidUtilities.statusBarHeight;
        flTitleBarContainer.setLayoutParams(layoutParams);
        flTitleBarContainer.setPadding(0, AndroidUtilities.statusBarHeight, 0, 0);
        MryTextView tvTitle = (MryTextView) this.fragmentView.findViewById(R.attr.tv_title);
        tvTitle.setTextSize((AndroidUtilities.isTablet() || getParentActivity().getResources().getConfiguration().orientation != 2) ? 16.0f : 14.0f);
        ImageView ivBack = (ImageView) this.fragmentView.findViewById(R.attr.iv_back);
        ivBack.setBackground(Theme.createSelectorDrawable(Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_back).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$GroupShareActivity$QFABSPsnZq7-f35zl5CPFVu7sdE
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionbar$0$GroupShareActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initActionbar$0$GroupShareActivity(View v) {
        finishFragment();
    }

    private void initCodeContainer() {
        this.llContainer = (LinearLayout) this.fragmentView.findViewById(R.attr.ll_container);
        this.rlContainer = (RelativeLayout) this.fragmentView.findViewById(R.attr.rlContainer);
        this.bivGroupAvatar = (BackupImageView) this.fragmentView.findViewById(R.attr.bivGroupAvatar);
        this.tvGroupName = (MryTextView) this.fragmentView.findViewById(R.attr.tvGroupName);
        this.tvGroupNumber = (MryTextView) this.fragmentView.findViewById(R.attr.tvGroupNumber);
        this.ivQrCode = (MryImageView) this.fragmentView.findViewById(R.attr.ivQrCode);
        this.tvGroupMembers = (MryTextView) this.fragmentView.findViewById(R.attr.tvGroupMembers);
        this.ivGroupQrCode = (ImageView) this.fragmentView.findViewById(R.attr.ivGroupQrCode);
        this.tvSave = (MryTextView) this.fragmentView.findViewById(R.attr.tvSave);
        this.tvShareQrCode = (MryTextView) this.fragmentView.findViewById(R.attr.tvShareQrCode);
        this.progressBar = (ProgressBar) this.fragmentView.findViewById(R.attr.progress_bar);
        this.tvGroupNameParent = this.fragmentView.findViewById(R.attr.tvGroupNameParent);
        Bitmap defaultBitmap = Bitmap.createBitmap(AndroidUtilities.dp(500.0f), AndroidUtilities.dp(500.0f), Bitmap.Config.ARGB_4444);
        this.ivGroupQrCode.setImageBitmap(defaultBitmap);
        this.bivGroupAvatar.getImageReceiver().setRoundRadius(AndroidUtilities.dp(30.0f));
        setViewData();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
    }

    private void setViewData() {
        this.tvGroupNameParent.getViewTreeObserver().addOnGlobalLayoutListener(this.changeNameWidthListener);
        if (this.chat != null) {
            AvatarDrawable avatarDrawable = new AvatarDrawable(this.chat);
            avatarDrawable.setColor(Theme.getColor(Theme.key_avatar_backgroundInProfileBlue));
            this.bivGroupAvatar.setImage(ImageLocation.getForChat(this.chat, false), "50_50", avatarDrawable, this.chat);
            this.tvGroupName.setText(this.chat.title);
            if (!TextUtils.isEmpty(this.chatInfo.about)) {
                this.tvGroupMembers.setText(this.chatInfo.about);
            } else {
                this.tvGroupMembers.setText(LocaleController.getString("OwnerLazyToNothing", R.string.OwnerLazyToNothing));
            }
            this.tvGroupMembers.setText(LocaleController.getString("GroupNumber", R.string.GroupNumber) + this.chat.username);
            this.tvGroupNumber.setText(SQLBuilder.PARENTHESES_LEFT + this.chat.participants_count + LocaleController.getString("GroupPeople", R.string.GroupPeople) + SQLBuilder.PARENTHESES_RIGHT);
            this.tvSave.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.GroupShareActivity.2
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    boolean isSave = GroupShareActivity.saveImageToGallery(GroupShareActivity.this.mContext, GroupShareActivity.getCacheBitmapFromView(GroupShareActivity.this.rlContainer), "GroupShare.png");
                    if (isSave) {
                        ToastUtils.show((CharSequence) LocaleController.getString("MeSavedSuccessfully", R.string.MeSavedSuccessfully));
                    } else {
                        ToastUtils.show((CharSequence) LocaleController.getString("MeSaveFailed", R.string.MeSaveFailed));
                    }
                }
            });
            this.tvShareQrCode.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$GroupShareActivity$QHz0DcfTIiXRE0Lbg32wrZ3Akbk
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$setViewData$1$GroupShareActivity(view);
                }
            });
        }
    }

    public /* synthetic */ void lambda$setViewData$1$GroupShareActivity(View v) {
        try {
            Intent intent = new Intent("android.intent.action.SEND");
            intent.setType("text/plain");
            intent.putExtra("android.intent.extra.TEXT", this.ret);
            getParentActivity().startActivityForResult(Intent.createChooser(intent, LocaleController.getString("BotShare", R.string.BotShare)), SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void createQRCode() {
        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$GroupShareActivity$1jW7taio3AUMaGBGy6H5GG9nH3o
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$createQRCode$3$GroupShareActivity();
            }
        }).start();
    }

    public /* synthetic */ void lambda$createQRCode$3$GroupShareActivity() {
        String preStr = getMessagesController().sharePrefix + "&Key=";
        this.bivGroupAvatar.getImageReceiver().getBitmap();
        Bitmap logo = BitmapFactory.decodeResource(this.mContext.getResources(), R.id.ic_logo);
        Bitmap groupBitmap = null;
        Bitmap bitmap = null;
        StringBuilder builder = new StringBuilder();
        if (this.chat != null) {
            TLRPC.User user = UserConfig.getInstance(UserConfig.selectedAccount).getCurrentUser();
            builder.append("PUid=");
            builder.append(user.id);
            builder.append("#Hash=");
            builder.append(user.access_hash);
            builder.append("#Uname=");
            builder.append(this.chat.username);
            String strEncodeToString = Base64.encodeToString(builder.toString().getBytes(), 2);
            this.ret = strEncodeToString;
            this.ret = strEncodeToString.replace("=", "%3D");
            String str = preStr + this.ret;
            this.ret = str;
            bitmap = CodeUtils.createQRCode(str, AndroidUtilities.dp(500.0f), toRoundCorner(logo, AndroidUtilities.dp(5.0f)));
            groupBitmap = CodeUtils.createQRCode(this.ret, AndroidUtilities.dp(500.0f), (Bitmap) null);
        }
        final Bitmap finalLogoBitmap = bitmap;
        final Bitmap finalGroupBitmap = groupBitmap;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.chats.-$$Lambda$GroupShareActivity$upS3D6R09JJBjOUlyaBc3xSNp38
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$GroupShareActivity(finalLogoBitmap, finalGroupBitmap);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$GroupShareActivity(Bitmap finalLogoBitmap, Bitmap finalGroupBitmap) {
        this.progressBar.setVisibility(8);
        this.ivQrCode.setImageBitmap(finalLogoBitmap);
        this.ivGroupQrCode.setImageBitmap(finalGroupBitmap);
    }

    public static boolean saveImageToGallery(Context context, Bitmap bitmap, String fileName) {
        String storePath = Environment.getExternalStorageDirectory().getAbsolutePath() + File.separator + "GroupQrcode";
        File appDir = new File(storePath);
        if (!appDir.exists()) {
            appDir.mkdir();
        }
        File file = new File(appDir, fileName);
        try {
            FileOutputStream fos = new FileOutputStream(file);
            boolean isSuccess = bitmap.compress(Bitmap.CompressFormat.JPEG, 80, fos);
            fos.flush();
            fos.close();
            Uri uri = Uri.fromFile(file);
            context.sendBroadcast(new Intent("android.intent.action.MEDIA_SCANNER_SCAN_FILE", uri));
            if (!isSuccess) {
                return false;
            }
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static Bitmap toRoundCorner(Bitmap bitmap, int pixels) {
        if (bitmap == null) {
            return null;
        }
        Bitmap output = Bitmap.createBitmap(bitmap.getWidth(), bitmap.getHeight(), Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(output);
        Paint paint = new Paint();
        Rect rect = new Rect(0, 0, bitmap.getWidth(), bitmap.getHeight());
        RectF rectF = new RectF(rect);
        float roundPx = pixels;
        paint.setAntiAlias(true);
        canvas.drawARGB(0, 0, 0, 0);
        paint.setColor(-12434878);
        canvas.drawRoundRect(rectF, roundPx, roundPx, paint);
        paint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.SRC_IN));
        canvas.drawBitmap(bitmap, rect, rect, paint);
        return output;
    }

    public static Bitmap getCacheBitmapFromView(View view) {
        view.setDrawingCacheEnabled(true);
        view.buildDrawingCache(true);
        Bitmap drawingCache = view.getDrawingCache();
        if (drawingCache != null) {
            Bitmap bitmap = Bitmap.createBitmap(drawingCache);
            view.setDrawingCacheEnabled(false);
            return bitmap;
        }
        return null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        super.onActivityResultFragment(requestCode, resultCode, data);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.chatInfoDidLoad && (args[1] instanceof TLRPC.ChatFull)) {
            TLRPC.ChatFull ci = (TLRPC.ChatFull) args[1];
            if (this.chatInfo != null && ci.id == this.chatInfo.id) {
                setViewData();
            }
        }
    }

    public Bitmap zoomImage(Bitmap bgimage, double newWidth, double newHeight) {
        float width = bgimage.getWidth();
        float height = bgimage.getHeight();
        Matrix matrix = new Matrix();
        float f = ((float) newWidth) / width;
        float f2 = ((float) newHeight) / height;
        Bitmap bitmap = Bitmap.createBitmap(bgimage, 0, 0, (int) width, (int) height, matrix, true);
        return bitmap;
    }

    public Bitmap captureView(View view) throws Throwable {
        Bitmap bm = Bitmap.createBitmap(view.getWidth(), view.getHeight(), Bitmap.Config.ARGB_8888);
        view.draw(new Canvas(bm));
        return bm;
    }

    public void setChat(TLRPC.Chat chat) {
        this.chat = chat;
    }

    public void setChatInfo(TLRPC.ChatFull chatInfo) {
        this.chatInfo = chatInfo;
    }
}
