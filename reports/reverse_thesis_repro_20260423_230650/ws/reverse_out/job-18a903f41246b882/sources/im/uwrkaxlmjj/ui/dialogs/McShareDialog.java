package im.uwrkaxlmjj.ui.dialogs;

import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.RelativeLayout;
import androidx.core.content.FileProvider;
import com.blankj.utilcode.util.ImageUtils;
import com.king.zxing.util.CodeUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.fragments.BaseFmts;
import im.uwrkaxlmjj.ui.hviews.MryImageView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class McShareDialog {
    private TLRPC.Chat chat;
    private Dialog dialog;
    private MryImageView ivCancel;
    private MryImageView ivCopy;
    private MryImageView ivQrCode;
    private MryImageView ivShareQrCode;
    private BaseFmts mBaseFmts;
    private Context mContext;
    private AlertDialog progressDialog;
    private String ret;
    private RelativeLayout rlContainer;
    private MCDailyTaskShareBean shareData;
    private Dialog shareDialog;
    private MryTextView tvInfo;
    private MryTextView tvSave;
    private MryTextView tvShare;
    private MryTextView tvTitle;
    private MryTextView tvUrl;
    private TLRPC.User user;

    public McShareDialog(Context context, BaseFmts baseFmts) {
        this.mContext = context;
        this.mBaseFmts = baseFmts;
    }

    public void initData() {
        showShareView();
    }

    private void showShareView() {
        View toastRoot = LayoutInflater.from(this.mContext).inflate(R.layout.dialog_mc_share_show, (ViewGroup) null);
        this.tvTitle = (MryTextView) toastRoot.findViewById(R.attr.tvTitle);
        this.tvInfo = (MryTextView) toastRoot.findViewById(R.attr.tvInfo);
        this.ivQrCode = (MryImageView) toastRoot.findViewById(R.attr.ivQrCode);
        this.tvSave = (MryTextView) toastRoot.findViewById(R.attr.tvSave);
        this.tvShare = (MryTextView) toastRoot.findViewById(R.attr.tvShare);
        this.ivCopy = (MryImageView) toastRoot.findViewById(R.attr.ivCopy);
        this.tvUrl = (MryTextView) toastRoot.findViewById(R.attr.tvUrl);
        this.ivCancel = (MryImageView) toastRoot.findViewById(R.attr.ivCancel);
        this.tvTitle.setText(LocaleController.getString("MeInviteFriends", R.string.MeInviteFriends));
        this.tvInfo.setText(LocaleController.getString("ScanQRcodeAddFriend", R.string.ScanQRcodeAddFriend));
        this.tvSave.setText(LocaleController.getString("SavePicture", R.string.SavePicture));
        this.tvShare.setText(LocaleController.getString("InviteNow", R.string.InviteNow));
        View shareView = LayoutInflater.from(this.mContext).inflate(R.layout.mc_share_view, (ViewGroup) null);
        this.rlContainer = (RelativeLayout) shareView.findViewById(R.attr.rlContainer);
        this.ivShareQrCode = (MryImageView) shareView.findViewById(R.attr.ivQrCode);
        Dialog dialog = new Dialog(this.mContext);
        this.shareDialog = dialog;
        dialog.getWindow().setBackgroundDrawable(new ColorDrawable());
        this.shareDialog.setContentView(shareView);
        this.shareDialog.show();
        setFullScreen(this.shareDialog);
        createQRCode();
        Dialog dialog2 = new Dialog(this.mContext);
        this.dialog = dialog2;
        dialog2.setContentView(toastRoot);
        this.dialog.show();
        setFullScreen(this.dialog);
        this.dialog.getWindow().setBackgroundDrawable(new ColorDrawable());
        this.dialog.setCancelable(false);
        this.tvSave.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.McShareDialog.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                boolean isSave = McShareDialog.saveImageToGallery(McShareDialog.this.mContext, McShareDialog.getCacheBitmapFromView(McShareDialog.this.rlContainer), "InviteFriendsShare.png");
                if (isSave) {
                    ToastUtils.show((CharSequence) LocaleController.getString("MeSavedSuccessfully", R.string.MeSavedSuccessfully));
                } else {
                    ToastUtils.show((CharSequence) LocaleController.getString("MeSaveFailed", R.string.MeSaveFailed));
                }
            }
        });
        this.ivCopy.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.McShareDialog.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                McShareDialog.this.copy();
                McShareDialog.this.shareDialog.dismiss();
            }
        });
        this.ivCancel.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.McShareDialog.3
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                McShareDialog.this.dialog.dismiss();
                McShareDialog.this.shareDialog.dismiss();
            }
        });
        this.tvShare.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.McShareDialog.4
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                McShareDialog.this.shareText();
                McShareDialog.this.shareDialog.dismiss();
            }
        });
    }

    public void setFullScreen(Dialog dialog) {
        Window dialogWindow = dialog.getWindow();
        if (dialogWindow != null) {
            dialogWindow.setFlags(1024, 1024);
            dialogWindow.getDecorView().setPadding(0, 0, 0, 0);
            WindowManager.LayoutParams layoutParams = dialogWindow.getAttributes();
            layoutParams.width = -1;
            layoutParams.height = -1;
            if (Build.VERSION.SDK_INT >= 28) {
                WindowManager.LayoutParams lp = dialogWindow.getAttributes();
                lp.layoutInDisplayCutoutMode = 1;
                dialogWindow.setAttributes(lp);
                View decorView = dialogWindow.getDecorView();
                decorView.setSystemUiVisibility(1280);
            }
            dialogWindow.setAttributes(layoutParams);
        }
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

    public static boolean saveImageToGallery(Context context, Bitmap bitmap, String fileName) {
        String storePath = Environment.getExternalStorageDirectory().getAbsolutePath() + File.separator + "qrcode";
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

    /* JADX INFO: Access modifiers changed from: private */
    public void shareText() {
        try {
            Intent intent = new Intent("android.intent.action.SEND");
            intent.setType("text/plain");
            intent.putExtra("android.intent.extra.TEXT", this.ret);
            this.mBaseFmts.getParentActivity().startActivityForResult(Intent.createChooser(intent, LocaleController.getString("BotShare", R.string.BotShare)), SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void share() {
        if (this.ivShareQrCode.getDrawable() == null || this.mContext == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 23 && this.mContext.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0) {
            this.mBaseFmts.getActivity().requestPermissions(new String[]{"android.permission.WRITE_EXTERNAL_STORAGE"}, 804);
            return;
        }
        File f = new File(FileLoader.getDirectory(0), System.currentTimeMillis() + ".jpg");
        boolean tag = ImageUtils.save(getCacheBitmapFromView(this.rlContainer), f, Bitmap.CompressFormat.JPEG, false);
        if (!tag) {
            ToastUtils.show(R.string.SaveFailed);
            return;
        }
        Intent intent = new Intent("android.intent.action.SEND");
        intent.setType("image/jpeg");
        if (Build.VERSION.SDK_INT >= 24) {
            try {
                intent.putExtra("android.intent.extra.STREAM", FileProvider.getUriForFile(this.mContext, "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", f));
                intent.setFlags(1);
            } catch (Exception e) {
                intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(f));
            }
        } else {
            intent.putExtra("android.intent.extra.STREAM", Uri.fromFile(f));
        }
        this.mBaseFmts.getActivity().startActivityForResult(Intent.createChooser(intent, LocaleController.getString("ShareQrCode", R.string.ShareQrCode)), SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void copy() {
        ClipboardManager clipboard = (ClipboardManager) ApplicationLoader.applicationContext.getSystemService("clipboard");
        ClipData clip = ClipData.newPlainText("label", this.ret);
        clipboard.setPrimaryClip(clip);
        ToastUtils.show(R.string.CopySuccess);
    }

    private void createQRCode() {
        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.dialogs.-$$Lambda$McShareDialog$xWfWWlHCWktCsFggcpGPp2fpj1o
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$createQRCode$1$McShareDialog();
            }
        }).start();
    }

    public /* synthetic */ void lambda$createQRCode$1$McShareDialog() {
        String preStr = this.mBaseFmts.getMessagesController().sharePrefix + "&Key=";
        Bitmap logo = BitmapFactory.decodeResource(this.mContext.getResources(), R.id.ic_logo);
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
            bitmap = CodeUtils.createQRCode(str2, AndroidUtilities.dp(500.0f), (Bitmap) null);
        }
        final Bitmap finalBitmap = bitmap;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.dialogs.-$$Lambda$McShareDialog$mC1hl7fcrZ9l_tF50ZbOi4Gmd9c
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$McShareDialog(finalBitmap);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$McShareDialog(Bitmap finalBitmap) {
        this.ivQrCode.setImageBitmap(finalBitmap);
        this.ivShareQrCode.setImageBitmap(finalBitmap);
        this.tvUrl.setText(this.ret);
    }

    public void setUser(TLRPC.User user) {
        this.user = user;
    }

    public void setChat(TLRPC.Chat chat) {
        this.chat = chat;
    }

    public class MCDailyTaskShareBean {
        public String url;

        public MCDailyTaskShareBean() {
        }
    }
}
