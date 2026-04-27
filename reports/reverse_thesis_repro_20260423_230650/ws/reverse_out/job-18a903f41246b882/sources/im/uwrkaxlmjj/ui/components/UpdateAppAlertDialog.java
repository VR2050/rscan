package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.ColorStateList;
import android.graphics.drawable.ClipDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.LayerDrawable;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.Display;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import com.blankj.utilcode.util.AppUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.utils.AppUpdater;
import im.uwrkaxlmjj.ui.utils.DownloadUtils;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class UpdateAppAlertDialog extends Dialog implements NotificationCenter.NotificationCenterDelegate {
    private int accountNum;
    private TLRPC.TL_help_appUpdate appUpdate;
    private MryTextView btnDownload;
    private MryTextView btnLeft;
    private MryTextView btnRight;
    private View container;
    private LinearLayout containerBottom;
    private View containerDownloadApp;
    private View containerScrollView;
    private View dividerHorzontial;
    private String fileName;
    private ImageView iv;
    private boolean mIsShowProgress;
    private Activity parentActivity;
    private AnimatorSet progressAnimation;
    private ProgressBar progressBar;
    private TextView tvContent;
    private MryTextView tvDownloadTips;
    private MryTextView tvPercent;
    private MryTextView tvSize;
    private MryTextView tvTitle;

    public UpdateAppAlertDialog(Activity activity, TLRPC.TL_help_appUpdate update, int account) {
        super(activity, 0);
        this.appUpdate = update;
        this.accountNum = account;
        if (update.document instanceof TLRPC.TL_document) {
            this.fileName = FileLoader.getAttachFileName(update.document);
        }
        this.parentActivity = activity;
        init(activity);
    }

    private void init(Context context) {
        String contextText;
        View view = LayoutInflater.from(context).inflate(R.layout.dialog_app_update, (ViewGroup) null, false);
        setContentView(view, new ViewGroup.LayoutParams(-1, -2));
        Window window = getWindow();
        window.setBackgroundDrawable(new ColorDrawable());
        window.setGravity(17);
        WindowManager wm = ((Activity) context).getWindowManager();
        Display display = wm.getDefaultDisplay();
        WindowManager.LayoutParams lp = window.getAttributes();
        lp.width = (display.getWidth() / 4) * 3;
        window.setAttributes(lp);
        this.container = view.findViewById(R.attr.container);
        view.setFitsSystemWindows(Build.VERSION.SDK_INT >= 21);
        this.container.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(15.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.containerScrollView = view.findViewById(R.attr.containerScrollView);
        this.containerDownloadApp = view.findViewById(R.attr.containerDownloadApp);
        this.dividerHorzontial = view.findViewById(R.attr.dividerHorzontial);
        this.iv = (ImageView) view.findViewById(R.attr.iv);
        this.tvTitle = (MryTextView) view.findViewById(R.attr.tvTitle);
        this.tvContent = (TextView) view.findViewById(R.attr.tvContent);
        this.containerBottom = (LinearLayout) view.findViewById(R.attr.containerBottom);
        this.btnLeft = (MryTextView) view.findViewById(R.attr.btnLeft);
        this.btnRight = (MryTextView) view.findViewById(R.attr.btnRight);
        this.tvPercent = (MryTextView) view.findViewById(R.attr.tvPercent);
        this.tvSize = (MryTextView) view.findViewById(R.attr.tvSize);
        this.progressBar = (ProgressBar) view.findViewById(R.attr.progressBar);
        this.tvDownloadTips = (MryTextView) view.findViewById(R.attr.tvDownloadTips);
        this.btnDownload = (MryTextView) view.findViewById(R.attr.btnDownload);
        View divider = view.findViewById(R.attr.divider);
        divider.setBackgroundColor(Theme.getColor(Theme.key_divider));
        this.tvTitle.setTextColor(Theme.key_windowBackgroundWhiteBlackText);
        this.tvContent.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
        this.tvContent.setLinkTextColor(Theme.getColor(Theme.key_dialogTextLink));
        this.btnLeft.setTextColor(Theme.key_windowBackgroundWhiteGrayText5);
        this.btnRight.setTextColor(Theme.key_windowBackgroundWhiteBlueText);
        this.tvDownloadTips.setTextColor(Theme.key_windowBackgroundWhiteGrayText5);
        this.btnDownload.setTextColor(Theme.key_windowBackgroundWhiteGrayText5);
        this.tvPercent.setTextColor(Theme.key_windowBackgroundWhiteGrayText5);
        this.tvSize.setTextColor(Theme.key_windowBackgroundWhiteGrayText5);
        this.btnDownload.setMryText(R.string.BackgroundDownload);
        this.tvContent.setMovementMethod(new AndroidUtilities.LinkMovementMethodMy());
        GradientDrawable p = new GradientDrawable();
        p.setCornerRadius(AndroidUtilities.dp(5.0f));
        p.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton));
        ClipDrawable progress = new ClipDrawable(p, 3, 1);
        GradientDrawable background = new GradientDrawable();
        background.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayLine));
        background.setCornerRadius(AndroidUtilities.dp(5.0f));
        LayerDrawable pd = new LayerDrawable(new Drawable[]{background, progress});
        this.progressBar.setProgressDrawable(pd);
        if (Build.VERSION.SDK_INT >= 21) {
            this.progressBar.setProgressBackgroundTintList(ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundGray)));
        }
        if (this.appUpdate != null) {
            this.tvTitle.setText(LocaleController.getString(R.string.NewVersionFound) + " V" + this.appUpdate.version);
            if (this.appUpdate.can_not_skip) {
                setCanceledOnTouchOutside(false);
                setCancelable(false);
                if (TextUtils.isEmpty(this.appUpdate.text)) {
                    contextText = LocaleController.getString(R.string.ForceUpdateTips);
                } else {
                    contextText = this.appUpdate.text;
                }
                this.iv.setVisibility(8);
                this.btnDownload.setVisibility(8);
                this.btnDownload.setEnabled(false);
            } else {
                setCanceledOnTouchOutside(true);
                setCancelable(true);
                setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$UpdateAppAlertDialog$cWi7TxuGuhGdfhVoYu1wkXMNL2c
                    @Override // android.content.DialogInterface.OnDismissListener
                    public final void onDismiss(DialogInterface dialogInterface) {
                        AppUpdater.dismissCheckUpdateTime = System.currentTimeMillis();
                    }
                });
                if (TextUtils.isEmpty(this.appUpdate.text)) {
                    contextText = LocaleController.getString(R.string.ForceNotUpdateDefaultTips);
                } else {
                    contextText = this.appUpdate.text;
                }
                this.iv.setVisibility(0);
                this.btnDownload.setEnabled(true);
            }
            this.tvContent.setText(contextText);
            this.btnLeft.setMryText(this.appUpdate.can_not_skip ? R.string.Exit : R.string.UpdateNextTimeCaps);
            this.btnLeft.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$UpdateAppAlertDialog$v32uG9jDZIEmiPQVXcHW4yILoWE
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$init$1$UpdateAppAlertDialog(view2);
                }
            });
            this.btnRight.setMryText(R.string.UpdateImmediatelyCaps);
            this.btnRight.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$UpdateAppAlertDialog$aiBdpAJnkphSfwovlBeXDYyeLVQ
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$init$2$UpdateAppAlertDialog(view2);
                }
            });
            this.btnDownload.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$UpdateAppAlertDialog$J9keev55nMuZu585wJ-MktH9pas
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$init$3$UpdateAppAlertDialog(view2);
                }
            });
        }
    }

    public /* synthetic */ void lambda$init$1$UpdateAppAlertDialog(View v) {
        if (this.appUpdate.can_not_skip) {
            Activity activity = this.parentActivity;
            if (activity != null) {
                activity.finish();
            }
        } else if (this.appUpdate.document instanceof TLRPC.TL_document) {
            FileLoader.getInstance(this.accountNum).cancelLoadFile(this.appUpdate.document);
        }
        dismiss();
    }

    public /* synthetic */ void lambda$init$2$UpdateAppAlertDialog(View v) {
        if (TextUtils.isEmpty(BuildVars.PLAYSTORE_APP_URL) && !BlockingUpdateView.checkApkInstallPermissions(getContext())) {
            return;
        }
        if (TextUtils.isEmpty(BuildVars.PLAYSTORE_APP_URL) && Build.VERSION.SDK_INT >= 23 && this.parentActivity.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0) {
            this.parentActivity.requestPermissions(new String[]{"android.permission.WRITE_EXTERNAL_STORAGE"}, 4);
            return;
        }
        if (this.appUpdate.document instanceof TLRPC.TL_document) {
            if (!BlockingUpdateView.openApkInstall(this.parentActivity, this.appUpdate.document)) {
                FileLoader.getInstance(this.accountNum).loadFile(this.appUpdate.document, "update", 1, 1);
                showProgress(true);
                return;
            }
            return;
        }
        if (this.appUpdate.url != null) {
            if (!TextUtils.isEmpty(BuildVars.PLAYSTORE_APP_URL)) {
                if (AppUtils.isAppInstalled("com.android.vending")) {
                    Browser.openUrl(this.parentActivity, BuildVars.PLAYSTORE_APP_URL);
                    return;
                } else {
                    ToastUtils.show(R.string.InstallGooglePlayTips);
                    return;
                }
            }
            DownloadUtils.getInstance(this.parentActivity).setDownloadListener(new DownloadUtils.DownloadListener() { // from class: im.uwrkaxlmjj.ui.components.UpdateAppAlertDialog.1
                @Override // im.uwrkaxlmjj.ui.utils.DownloadUtils.DownloadListener
                public void onStart() {
                    UpdateAppAlertDialog.this.showProgress(true);
                }

                @Override // im.uwrkaxlmjj.ui.utils.DownloadUtils.DownloadListener
                public void onProgress(int percent, long soFarSize, long totalSize) {
                    if (UpdateAppAlertDialog.this.progressBar != null) {
                        UpdateAppAlertDialog.this.progressBar.setProgress(percent);
                    }
                    if (UpdateAppAlertDialog.this.tvPercent != null) {
                        UpdateAppAlertDialog.this.tvPercent.setText(percent + "%");
                    }
                    if (UpdateAppAlertDialog.this.tvSize != null) {
                        UpdateAppAlertDialog.this.tvSize.setText(soFarSize + "KB / " + totalSize + "KB");
                    }
                }

                @Override // im.uwrkaxlmjj.ui.utils.DownloadUtils.DownloadListener
                public void onFinish(String fileFullPath, long totalSize) {
                    UpdateAppAlertDialog.this.dismiss();
                }

                @Override // im.uwrkaxlmjj.ui.utils.DownloadUtils.DownloadListener
                public void onFailed() {
                }
            }).startDownload(this.appUpdate.url, this.appUpdate.version);
        }
    }

    public /* synthetic */ void lambda$init$3$UpdateAppAlertDialog(View v) {
        ToastUtils.show(R.string.AlreadyBackgroundDownloading);
        dismiss();
    }

    @Override // android.app.Dialog
    public void show() {
        super.show();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.fileDidLoad) {
            String location = (String) args[0];
            String str = this.fileName;
            if (str != null && str.equals(location)) {
                showProgress(false);
                BlockingUpdateView.openApkInstall(this.parentActivity, this.appUpdate.document);
                return;
            }
            return;
        }
        if (id == NotificationCenter.fileDidFailToLoad) {
            String location2 = (String) args[0];
            String str2 = this.fileName;
            if (str2 != null && str2.equals(location2)) {
                showProgress(false);
                return;
            }
            return;
        }
        if (id == NotificationCenter.FileLoadProgressChanged) {
            String location3 = (String) args[0];
            String str3 = this.fileName;
            if (str3 != null && str3.equals(location3)) {
                Float loadProgress = (Float) args[1];
                showProgress(true);
                ProgressBar progressBar = this.progressBar;
                if (progressBar != null) {
                    progressBar.setProgress(loadProgress.intValue());
                }
            }
        }
    }

    @Override // android.app.Dialog
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        NotificationCenter.getInstance(this.accountNum).addObserver(this, NotificationCenter.fileDidLoad);
        NotificationCenter.getInstance(this.accountNum).addObserver(this, NotificationCenter.fileDidFailToLoad);
        NotificationCenter.getInstance(this.accountNum).addObserver(this, NotificationCenter.FileLoadProgressChanged);
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        super.dismiss();
        NotificationCenter.getInstance(this.accountNum).removeObserver(this, NotificationCenter.fileDidLoad);
        NotificationCenter.getInstance(this.accountNum).removeObserver(this, NotificationCenter.fileDidFailToLoad);
        NotificationCenter.getInstance(this.accountNum).removeObserver(this, NotificationCenter.FileLoadProgressChanged);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showProgress(final boolean show) {
        if (this.btnDownload == null || this.containerBottom == null || this.containerDownloadApp == null || this.containerScrollView == null || this.iv == null || this.mIsShowProgress == show) {
            return;
        }
        this.mIsShowProgress = show;
        AnimatorSet animatorSet = this.progressAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.progressAnimation = new AnimatorSet();
        if (!show) {
            ProgressBar progressBar = this.progressBar;
            if (progressBar != null) {
                progressBar.setProgress(0);
            }
            TLRPC.TL_help_appUpdate tL_help_appUpdate = this.appUpdate;
            if (tL_help_appUpdate != null && !tL_help_appUpdate.can_not_skip) {
                this.iv.setVisibility(0);
            }
            this.containerScrollView.setVisibility(0);
            this.containerBottom.setVisibility(0);
            this.btnDownload.setEnabled(false);
            this.progressAnimation.playTogether(ObjectAnimator.ofFloat(this.btnDownload, "scaleX", 0.1f), ObjectAnimator.ofFloat(this.btnDownload, "scaleY", 0.1f), ObjectAnimator.ofFloat(this.btnDownload, "alpha", 0.0f), ObjectAnimator.ofFloat(this.containerDownloadApp, "scaleX", 0.1f), ObjectAnimator.ofFloat(this.containerDownloadApp, "scaleY", 0.1f), ObjectAnimator.ofFloat(this.containerDownloadApp, "alpha", 0.0f), ObjectAnimator.ofFloat(this.iv, "scaleX", 1.0f), ObjectAnimator.ofFloat(this.iv, "scaleY", 1.0f), ObjectAnimator.ofFloat(this.iv, "alpha", 1.0f), ObjectAnimator.ofFloat(this.containerBottom, "scaleX", 1.0f), ObjectAnimator.ofFloat(this.containerBottom, "scaleY", 1.0f), ObjectAnimator.ofFloat(this.containerBottom, "alpha", 1.0f), ObjectAnimator.ofFloat(this.containerScrollView, "scaleX", 1.0f), ObjectAnimator.ofFloat(this.containerScrollView, "scaleY", 1.0f), ObjectAnimator.ofFloat(this.containerScrollView, "alpha", 1.0f));
        } else {
            this.containerDownloadApp.setVisibility(0);
            TLRPC.TL_help_appUpdate tL_help_appUpdate2 = this.appUpdate;
            if (tL_help_appUpdate2 != null && !tL_help_appUpdate2.can_not_skip) {
                this.btnDownload.setVisibility(0);
                this.btnDownload.setEnabled(true);
            }
            this.btnDownload.setEnabled(true);
            this.progressAnimation.playTogether(ObjectAnimator.ofFloat(this.iv, "scaleX", 0.1f), ObjectAnimator.ofFloat(this.iv, "scaleY", 0.1f), ObjectAnimator.ofFloat(this.iv, "alpha", 0.0f), ObjectAnimator.ofFloat(this.containerBottom, "scaleX", 0.1f), ObjectAnimator.ofFloat(this.containerBottom, "scaleY", 0.1f), ObjectAnimator.ofFloat(this.containerBottom, "alpha", 0.0f), ObjectAnimator.ofFloat(this.containerScrollView, "scaleX", 0.1f), ObjectAnimator.ofFloat(this.containerScrollView, "scaleY", 0.1f), ObjectAnimator.ofFloat(this.containerScrollView, "alpha", 0.0f), ObjectAnimator.ofFloat(this.btnDownload, "scaleX", 0.1f, 1.0f), ObjectAnimator.ofFloat(this.btnDownload, "scaleY", 0.1f, 1.0f), ObjectAnimator.ofFloat(this.btnDownload, "alpha", 0.1f, 1.0f), ObjectAnimator.ofFloat(this.containerDownloadApp, "scaleX", 0.1f, 1.0f), ObjectAnimator.ofFloat(this.containerDownloadApp, "scaleY", 0.1f, 1.0f), ObjectAnimator.ofFloat(this.containerDownloadApp, "alpha", 0.1f, 1.0f));
        }
        this.progressAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.UpdateAppAlertDialog.2
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                UpdateAppAlertDialog.this.container.requestLayout();
                if (UpdateAppAlertDialog.this.progressAnimation != null && UpdateAppAlertDialog.this.progressAnimation.equals(animation)) {
                    if (!show) {
                        if (UpdateAppAlertDialog.this.appUpdate != null && !UpdateAppAlertDialog.this.appUpdate.can_not_skip) {
                            UpdateAppAlertDialog.this.iv.setVisibility(0);
                        }
                        UpdateAppAlertDialog.this.containerScrollView.setVisibility(0);
                        UpdateAppAlertDialog.this.containerBottom.setVisibility(0);
                        UpdateAppAlertDialog.this.containerDownloadApp.setVisibility(8);
                        UpdateAppAlertDialog.this.btnDownload.setVisibility(8);
                        return;
                    }
                    UpdateAppAlertDialog.this.iv.setVisibility(8);
                    UpdateAppAlertDialog.this.containerScrollView.setVisibility(8);
                    UpdateAppAlertDialog.this.containerBottom.setVisibility(8);
                    UpdateAppAlertDialog.this.containerDownloadApp.setVisibility(0);
                    if (UpdateAppAlertDialog.this.appUpdate != null) {
                        if (!UpdateAppAlertDialog.this.appUpdate.can_not_skip) {
                            UpdateAppAlertDialog.this.btnDownload.setVisibility(0);
                        } else {
                            UpdateAppAlertDialog.this.dividerHorzontial.setVisibility(8);
                        }
                    }
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (UpdateAppAlertDialog.this.progressAnimation != null && UpdateAppAlertDialog.this.progressAnimation.equals(animation)) {
                    UpdateAppAlertDialog.this.progressAnimation = null;
                }
            }
        });
        this.progressAnimation.setDuration(150L);
        this.progressAnimation.start();
    }
}
