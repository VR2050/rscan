package im.uwrkaxlmjj.ui.hui.mine;

import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.text.TextUtils;
import android.util.Base64;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.content.FileProvider;
import com.blankj.utilcode.util.ImageUtils;
import com.king.zxing.util.CodeUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class QrCodeActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private ImageView QRCodeImage;
    private BackupImageView avatarImage;
    private MryTextView btnSave;
    private MryTextView btnShare;
    private ViewTreeObserver.OnGlobalLayoutListener changeNameWidthListener = new ViewTreeObserver.OnGlobalLayoutListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.QrCodeActivity.1
        @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
        public void onGlobalLayout() {
            int allw = QrCodeActivity.this.tvNameParent.getMeasuredWidth();
            if (allw > 0) {
                int plusw = QrCodeActivity.this.nameView.getMeasuredWidth() + QrCodeActivity.this.ivGender.getMeasuredWidth();
                if (plusw > allw) {
                    QrCodeActivity.this.fragmentView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                    ViewGroup.LayoutParams lpName = QrCodeActivity.this.nameView.getLayoutParams();
                    lpName.width = (allw - QrCodeActivity.this.ivGender.getMeasuredWidth()) - AndroidUtilities.dp(10.0f);
                    QrCodeActivity.this.nameView.setLayoutParams(lpName);
                }
            }
        }
    };
    private TLRPC.Chat chat;
    private View iconClose;
    private ImageView ivGender;
    private ImageView ivQrCode;
    private LinearLayout llContainer;
    private Context mContext;
    private MryTextView nameView;
    private MryTextView otherView;
    private ProgressBar progressBar;
    private String ret;
    private ConstraintLayout rlContainer;
    private View tvNameParent;
    private MryTextView tvQRCodeText;
    private TLRPC.User user;
    private TLRPCContacts.CL_userFull_v1 userFull;
    private int userId;
    private TLRPC.UserFull userInfo;

    public QrCodeActivity(int userId) {
        this.userId = userId;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        TLRPC.User user = getMessagesController().getUser(Integer.valueOf(this.userId));
        this.user = user;
        if (user == null) {
            return false;
        }
        TLRPC.UserFull full = getMessagesController().getUserFull(this.userId);
        if (full instanceof TLRPCContacts.CL_userFull_v1) {
            this.userFull = (TLRPCContacts.CL_userFull_v1) full;
        }
        getMessagesController().loadFullUser(this.userId, this.classGuid, true);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFullInfoDidLoad);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        if (this.fragmentView != null) {
            this.fragmentView.getViewTreeObserver().removeOnGlobalLayoutListener(this.changeNameWidthListener);
        }
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFullInfoDidLoad);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.actionBar.setAddToContainer(false);
        this.fragmentView = View.inflate(context, R.layout.activity_qr_code_layout, null);
        initActionbar();
        initCodeContainer();
        createQRCode();
        return this.fragmentView;
    }

    private void initActionbar() {
        View viewFindViewById = this.fragmentView.findViewById(R.attr.img_close);
        this.iconClose = viewFindViewById;
        viewFindViewById.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.QrCodeActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                QrCodeActivity.this.finishFragment();
            }
        });
    }

    private void initCodeContainer() {
        String str;
        this.tvNameParent = this.fragmentView.findViewById(R.attr.tvNameParent);
        this.ivQrCode = (ImageView) this.fragmentView.findViewById(R.attr.iv_qr_code);
        this.avatarImage = (BackupImageView) this.fragmentView.findViewById(R.attr.biv_avatar);
        this.nameView = (MryTextView) this.fragmentView.findViewById(R.attr.tv_name);
        this.otherView = (MryTextView) this.fragmentView.findViewById(R.attr.tv_other);
        this.ivGender = (ImageView) this.fragmentView.findViewById(R.attr.iv_gender);
        this.tvQRCodeText = (MryTextView) this.fragmentView.findViewById(R.attr.tv_qr_code_text);
        this.QRCodeImage = (ImageView) this.fragmentView.findViewById(R.attr.iv_qr_code);
        this.progressBar = (ProgressBar) this.fragmentView.findViewById(R.attr.progress_bar);
        this.btnShare = (MryTextView) this.fragmentView.findViewById(R.attr.tvShareQrCode);
        this.btnSave = (MryTextView) this.fragmentView.findViewById(R.attr.tvSave);
        Bitmap defaultBitmap = Bitmap.createBitmap(AndroidUtilities.dp(500.0f), AndroidUtilities.dp(500.0f), Bitmap.Config.ARGB_4444);
        this.QRCodeImage.setImageBitmap(defaultBitmap);
        this.avatarImage.getImageReceiver().setRoundRadius(AndroidUtilities.dp(7.5f));
        this.nameView.setTextSize(14.0f);
        this.otherView.setTextSize(14.0f);
        if (this.user != null) {
            AvatarDrawable avatarDrawable = new AvatarDrawable(this.user);
            avatarDrawable.setColor(Theme.getColor(Theme.key_avatar_backgroundInProfileBlue));
            this.avatarImage.setImage(ImageLocation.getForUser(this.user, false), "50_50", avatarDrawable, this.user);
            this.nameView.setText(UserObject.getName(this.user));
            MryTextView mryTextView = this.otherView;
            TLRPC.UserFull userFull = this.userInfo;
            if (userFull == null || TextUtils.isEmpty(userFull.user.username)) {
                str = "Account Exception";
            } else {
                str = LocaleController.getString("AppIdWithColon", R.string.AppIdWithColon) + this.userInfo.user.username;
            }
            mryTextView.setText(str);
            this.tvQRCodeText.setText(LocaleController.getString("QrCodeUserText", R.string.QrCodeUserText));
        } else if (this.chat != null) {
            AvatarDrawable avatarDrawable2 = new AvatarDrawable(this.chat);
            avatarDrawable2.setColor(Theme.getColor(Theme.key_avatar_backgroundInProfileBlue));
            this.avatarImage.setImage(ImageLocation.getForChat(this.chat, false), "50_50", avatarDrawable2, this.chat);
            this.nameView.setText(this.chat.title);
            this.otherView.setText(this.chat.username);
            this.tvQRCodeText.setText(LocaleController.getString("QrCodeChatText", R.string.QrCodeChatText));
        }
        this.btnSave.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$QrCodeActivity$Q9-mWB3T__S_KcuJ-kpxAgdaoiw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initCodeContainer$0$QrCodeActivity(view);
            }
        });
        this.btnShare.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$QrCodeActivity$HeLPYFXdJagVm-03o_4fEAgdHiM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initCodeContainer$1$QrCodeActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initCodeContainer$0$QrCodeActivity(View v) {
        save();
    }

    public /* synthetic */ void lambda$initCodeContainer$1$QrCodeActivity(View v) {
        shareText();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
    }

    private void setViewData() {
        String str;
        if (this.userFull.getExtendBean() != null && this.fragmentView != null) {
            this.fragmentView.getViewTreeObserver().addOnGlobalLayoutListener(this.changeNameWidthListener);
            int sex = this.userFull.getExtendBean().sex;
            int i = 0;
            this.ivGender.setImageResource(sex == 1 ? R.id.ic_male : sex == 2 ? R.id.ic_female : 0);
            ImageView imageView = this.ivGender;
            if (sex != 1 && sex != 2) {
                i = 8;
            }
            imageView.setVisibility(i);
            MryTextView mryTextView = this.otherView;
            TLRPC.UserFull userFull = this.userInfo;
            if (userFull == null || TextUtils.isEmpty(userFull.user.username)) {
                str = "Account Exception";
            } else {
                str = LocaleController.getString("AppIdWithColon", R.string.AppIdWithColon) + this.userInfo.user.username;
            }
            mryTextView.setText(str);
        }
    }

    private void createQRCode() {
        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$QrCodeActivity$kOMbxP0v7McKR_pYituX538w-_k
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$createQRCode$3$QrCodeActivity();
            }
        }).start();
    }

    public /* synthetic */ void lambda$createQRCode$3$QrCodeActivity() {
        String preStr = getMessagesController().sharePrefix + "&Key=";
        this.avatarImage.getImageReceiver().getBitmap();
        Bitmap logo = BitmapFactory.decodeResource(this.mContext.getResources(), R.id.ic_logo);
        Bitmap userBitmap = null;
        Bitmap bitmap = null;
        StringBuilder builder = new StringBuilder();
        if (this.user != null) {
            builder.append("PUid=");
            builder.append(this.user.id);
            builder.append("#Hash=");
            builder.append(this.user.access_hash);
            String strEncodeToString = Base64.encodeToString(builder.toString().getBytes(), 2);
            this.ret = strEncodeToString;
            this.ret = strEncodeToString.replace("=", "%3D");
            String str = preStr + this.ret;
            this.ret = str;
            bitmap = CodeUtils.createQRCode(str, AndroidUtilities.dp(500.0f), logo);
            userBitmap = CodeUtils.createQRCode(this.ret, AndroidUtilities.dp(500.0f), (Bitmap) null);
        } else if (this.chat != null) {
            builder.append("PUid=");
            builder.append(this.chat.id);
            builder.append("#Hash=");
            builder.append(this.chat.access_hash);
            builder.append("#Uname=");
            builder.append(this.chat.username);
            String strEncodeToString2 = Base64.encodeToString(builder.toString().getBytes(), 2);
            this.ret = strEncodeToString2;
            this.ret = strEncodeToString2.replace("=", "%3D");
            String str2 = preStr + this.ret;
            this.ret = str2;
            bitmap = CodeUtils.createQRCode(str2, AndroidUtilities.dp(500.0f), logo);
            userBitmap = CodeUtils.createQRCode(this.ret, AndroidUtilities.dp(500.0f), (Bitmap) null);
        }
        final Bitmap finalLogoBitmap = bitmap;
        final Bitmap finalUserBitmap = userBitmap;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$QrCodeActivity$lX9Fmt1r-qUoR8_ARVszrmgLTps
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$QrCodeActivity(finalUserBitmap, finalLogoBitmap);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$QrCodeActivity(Bitmap finalUserBitmap, Bitmap finalLogoBitmap) {
        this.progressBar.setVisibility(8);
        this.QRCodeImage.setImageBitmap(finalUserBitmap);
        this.ivQrCode.setImageBitmap(finalLogoBitmap);
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

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.userFullInfoDidLoad) {
            Integer uid = (Integer) args[0];
            int i = this.userId;
            if (i != 0 && i == uid.intValue() && (args[1] instanceof TLRPCContacts.CL_userFull_v1)) {
                TLRPC.UserFull userFull = (TLRPC.UserFull) args[1];
                this.userInfo = userFull;
                this.userFull = (TLRPCContacts.CL_userFull_v1) userFull;
                this.user = userFull.user;
                setViewData();
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResultFragment(requestCode, permissions, grantResults);
        if (requestCode == 804 && grantResults != null && grantResults[0] == 0) {
            share();
        }
    }

    private void shareText() {
        try {
            Intent intent = new Intent("android.intent.action.SEND");
            intent.setType("text/plain");
            intent.putExtra("android.intent.extra.TEXT", this.ret);
            getParentActivity().startActivityForResult(Intent.createChooser(intent, LocaleController.getString("BotShare", R.string.BotShare)), SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void save() {
        boolean isSave = saveImageToGallery(this.mContext, getCacheBitmapFromView(this.fragmentView), "UserShare.png");
        if (isSave) {
            ToastUtils.show((CharSequence) LocaleController.getString("MeSavedSuccessfully", R.string.MeSavedSuccessfully));
        } else {
            ToastUtils.show((CharSequence) LocaleController.getString("MeSaveFailed", R.string.MeSaveFailed));
        }
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

    private void share() {
        if (this.QRCodeImage.getDrawable() == null || getParentActivity() == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0) {
            getParentActivity().requestPermissions(new String[]{"android.permission.WRITE_EXTERNAL_STORAGE"}, 804);
            return;
        }
        File f = new File(FileLoader.getDirectory(0), System.currentTimeMillis() + ".jpg");
        boolean tag = ImageUtils.save(getCacheBitmapFromView(this.fragmentView), f, Bitmap.CompressFormat.JPEG, false);
        if (!tag) {
            ToastUtils.show(R.string.SaveFailed);
            return;
        }
        Intent intent = new Intent("android.intent.action.SEND");
        intent.setType("image/*");
        if (Build.VERSION.SDK_INT >= 24) {
            try {
                intent.putExtra("android.intent.extra.STREAM", FileProvider.getUriForFile(getParentActivity(), "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", f));
                intent.setFlags(1);
            } catch (Exception e) {
                intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(f));
            }
        } else {
            intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(f));
        }
        getParentActivity().startActivityForResult(Intent.createChooser(intent, LocaleController.getString("ShareQrCode", R.string.ShareQrCode)), SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
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
}
