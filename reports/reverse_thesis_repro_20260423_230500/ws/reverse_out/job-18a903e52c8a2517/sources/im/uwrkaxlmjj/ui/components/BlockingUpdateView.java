package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Canvas;
import android.net.Uri;
import android.os.Build;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import com.blankj.utilcode.util.AppUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import im.uwrkaxlmjj.ui.utils.AppUpdater;
import im.uwrkaxlmjj.ui.utils.DownloadUtils;
import java.io.File;
import java.util.Locale;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class BlockingUpdateView extends FrameLayout implements NotificationCenter.NotificationCenterDelegate {
    private FrameLayout acceptButton;
    private MryRoundButton acceptTextView;
    private int accountNum;
    private TLRPC.TL_help_appUpdate appUpdate;
    private String fileName;
    private int pressCount;
    private AnimatorSet progressAnimation;
    private RadialProgress radialProgress;
    private FrameLayout radialProgressView;
    private TextView textView;

    public BlockingUpdateView(final Context context) {
        super(context);
        setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        int top = Build.VERSION.SDK_INT >= 21 ? (int) (AndroidUtilities.statusBarHeight / AndroidUtilities.density) : 0;
        FrameLayout view = new FrameLayout(context);
        view.setBackgroundColor(-11556378);
        addView(view, new FrameLayout.LayoutParams(-1, AndroidUtilities.dp(176.0f) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)));
        ImageView imageView = new ImageView(context);
        imageView.setImageResource(R.id.ic_logo);
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        imageView.setPadding(0, 0, 0, AndroidUtilities.dp(14.0f));
        view.addView(imageView, LayoutHelper.createFrame(-2.0f, -2.0f, 17, 0.0f, top, 0.0f, 0.0f));
        imageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$BlockingUpdateView$FXIWV-cWN1KFK6fBTB2zwPBAxMs
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$0$BlockingUpdateView(view2);
            }
        });
        ScrollView scrollView = new ScrollView(context);
        AndroidUtilities.setScrollViewEdgeEffectColor(scrollView, Theme.getColor(Theme.key_actionBarDefault));
        addView(scrollView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 27.0f, top + 206, 27.0f, 130.0f));
        FrameLayout container = new FrameLayout(context);
        scrollView.addView(container, LayoutHelper.createScroll(-1, -2, 17));
        TextView titleTextView = new TextView(context);
        titleTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        titleTextView.setTextSize(1, 20.0f);
        titleTextView.setGravity(49);
        titleTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        titleTextView.setText(LocaleController.getString("UpdateApp", R.string.UpdateApp));
        container.addView(titleTextView, LayoutHelper.createFrame(-2, -2, 49));
        TextView textView = new TextView(context);
        this.textView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.textView.setLinkTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteLinkText));
        this.textView.setTextSize(1, 15.0f);
        this.textView.setMovementMethod(new AndroidUtilities.LinkMovementMethodMy());
        this.textView.setGravity(49);
        this.textView.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
        container.addView(this.textView, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 0.0f, 44.0f, 0.0f, 0.0f));
        this.acceptButton = new FrameLayout(context);
        if (Build.VERSION.SDK_INT >= 21) {
            StateListAnimator animator = new StateListAnimator();
            animator.addState(new int[]{android.R.attr.state_pressed}, ObjectAnimator.ofFloat(this.acceptButton, "translationZ", AndroidUtilities.dp(2.0f), AndroidUtilities.dp(4.0f)).setDuration(200L));
            animator.addState(new int[0], ObjectAnimator.ofFloat(this.acceptButton, "translationZ", AndroidUtilities.dp(4.0f), AndroidUtilities.dp(2.0f)).setDuration(200L));
            this.acceptButton.setStateListAnimator(animator);
        }
        this.acceptButton.setPadding(AndroidUtilities.dp(20.0f), 0, AndroidUtilities.dp(20.0f), 0);
        addView(this.acceptButton, LayoutHelper.createFrame(-1.0f, 45.0f, 81, 60.0f, 0.0f, 60.0f, 45.0f));
        MryRoundButton mryRoundButton = new MryRoundButton(context);
        this.acceptTextView = mryRoundButton;
        mryRoundButton.setPrimaryRadiusAdjustBoundsFillStyle();
        this.acceptTextView.setBackgroundColor(-14904113);
        this.acceptTextView.setTextSize(16.0f);
        this.acceptTextView.setBold();
        this.acceptTextView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$BlockingUpdateView$pZk3T3bbVU3PRCL2mlV2ks7KHNo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$1$BlockingUpdateView(context, view2);
            }
        });
        this.acceptButton.addView(this.acceptTextView, LayoutHelper.createFrame(-1, 45, 17));
        FrameLayout frameLayout = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.BlockingUpdateView.1
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top2, int right, int bottom) {
                super.onLayout(changed, left, top2, right, bottom);
                int width = right - left;
                int height = bottom - top2;
                int w = AndroidUtilities.dp(36.0f);
                int l = (width - w) / 2;
                int t = (height - w) / 2;
                BlockingUpdateView.this.radialProgress.setProgressRect(l, t, l + w, t + w);
            }

            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                BlockingUpdateView.this.radialProgress.draw(canvas);
            }
        };
        this.radialProgressView = frameLayout;
        frameLayout.setWillNotDraw(false);
        this.radialProgressView.setAlpha(0.0f);
        this.radialProgressView.setScaleX(0.1f);
        this.radialProgressView.setScaleY(0.1f);
        this.radialProgressView.setVisibility(4);
        RadialProgress radialProgress = new RadialProgress(this.radialProgressView);
        this.radialProgress = radialProgress;
        radialProgress.setBackground(null, true, false);
        this.radialProgress.setProgressColor(-1);
        this.acceptButton.addView(this.radialProgressView, LayoutHelper.createFrame(36, 36, 17));
    }

    public /* synthetic */ void lambda$new$0$BlockingUpdateView(View v) {
        int i = this.pressCount + 1;
        this.pressCount = i;
        if (i >= 10) {
            setVisibility(8);
            AppUpdater.pendingAppUpdate = null;
            AppUpdater.getInstance(this.accountNum).lambda$loadUpdateConfig$2$AppUpdater();
        }
    }

    public /* synthetic */ void lambda$new$1$BlockingUpdateView(Context context, View view1) {
        if (TextUtils.isEmpty(BuildVars.PLAYSTORE_APP_URL) && !checkApkInstallPermissions(getContext())) {
            return;
        }
        if (TextUtils.isEmpty(BuildVars.PLAYSTORE_APP_URL) && Build.VERSION.SDK_INT >= 23 && context.checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") != 0) {
            ((LaunchActivity) context).requestPermissions(new String[]{"android.permission.WRITE_EXTERNAL_STORAGE"}, 4);
            return;
        }
        if (this.appUpdate.document instanceof TLRPC.TL_document) {
            if (!openApkInstall((Activity) getContext(), this.appUpdate.document)) {
                FileLoader.getInstance(this.accountNum).loadFile(this.appUpdate.document, "update", 2, 1);
                showProgress(true);
                return;
            }
            return;
        }
        if (this.appUpdate.url != null) {
            if (!TextUtils.isEmpty(BuildVars.PLAYSTORE_APP_URL)) {
                if (AppUtils.isAppInstalled("com.android.vending")) {
                    Browser.openUrl(context, BuildVars.PLAYSTORE_APP_URL);
                    return;
                } else {
                    ToastUtils.show(R.string.InstallGooglePlayTips);
                    return;
                }
            }
            DownloadUtils.getInstance(getContext()).startDownload(this.appUpdate.url, this.appUpdate.version);
        }
    }

    @Override // android.view.View
    public void setVisibility(int visibility) {
        super.setVisibility(visibility);
        if (visibility == 8) {
            NotificationCenter.getInstance(this.accountNum).removeObserver(this, NotificationCenter.fileDidLoad);
            NotificationCenter.getInstance(this.accountNum).removeObserver(this, NotificationCenter.fileDidFailToLoad);
            NotificationCenter.getInstance(this.accountNum).removeObserver(this, NotificationCenter.FileLoadProgressChanged);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.fileDidLoad) {
            String location = (String) args[0];
            String str = this.fileName;
            if (str != null && str.equals(location)) {
                showProgress(false);
                openApkInstall((Activity) getContext(), this.appUpdate.document);
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
                this.radialProgress.setProgress(loadProgress.floatValue(), true);
            }
        }
    }

    public static boolean checkApkInstallPermissions(final Context context) {
        if (Build.VERSION.SDK_INT >= 26 && !ApplicationLoader.applicationContext.getPackageManager().canRequestPackageInstalls()) {
            AlertDialog.Builder builder = new AlertDialog.Builder(context);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage(LocaleController.getString("ApkRestricted", R.string.ApkRestricted));
            builder.setPositiveButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$BlockingUpdateView$6eCmaGBgQURdkX3sTBp6qbVF4Ms
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    BlockingUpdateView.lambda$checkApkInstallPermissions$2(context, dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            builder.show();
            return false;
        }
        return true;
    }

    static /* synthetic */ void lambda$checkApkInstallPermissions$2(Context context, DialogInterface dialogInterface, int i) {
        try {
            context.startActivity(new Intent("android.settings.MANAGE_UNKNOWN_APP_SOURCES", Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName())));
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static boolean openApkInstall(Activity activity, TLRPC.Document document) {
        boolean exists = false;
        try {
            FileLoader.getAttachFileName(document);
            File f = FileLoader.getPathToAttach(document, true);
            boolean zExists = f.exists();
            exists = zExists;
            if (zExists) {
                Intent intent = new Intent("android.intent.action.VIEW");
                intent.setFlags(1);
                if (Build.VERSION.SDK_INT >= 24) {
                    intent.setDataAndType(FileProvider.getUriForFile(activity, "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", f), "application/vnd.android.package-archive");
                } else {
                    intent.setDataAndType(Uri.fromFile(f), "application/vnd.android.package-archive");
                }
                try {
                    activity.startActivityForResult(intent, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        return exists;
    }

    private void showProgress(final boolean show) {
        AnimatorSet animatorSet = this.progressAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.progressAnimation = new AnimatorSet();
        if (show) {
            this.radialProgressView.setVisibility(0);
            this.acceptButton.setEnabled(false);
            this.progressAnimation.playTogether(ObjectAnimator.ofFloat(this.acceptTextView, "scaleX", 0.1f), ObjectAnimator.ofFloat(this.acceptTextView, "scaleY", 0.1f), ObjectAnimator.ofFloat(this.acceptTextView, "alpha", 0.0f), ObjectAnimator.ofFloat(this.radialProgressView, "scaleX", 1.0f), ObjectAnimator.ofFloat(this.radialProgressView, "scaleY", 1.0f), ObjectAnimator.ofFloat(this.radialProgressView, "alpha", 1.0f));
        } else {
            this.acceptTextView.setVisibility(0);
            this.acceptButton.setEnabled(true);
            this.progressAnimation.playTogether(ObjectAnimator.ofFloat(this.radialProgressView, "scaleX", 0.1f), ObjectAnimator.ofFloat(this.radialProgressView, "scaleY", 0.1f), ObjectAnimator.ofFloat(this.radialProgressView, "alpha", 0.0f), ObjectAnimator.ofFloat(this.acceptTextView, "scaleX", 1.0f), ObjectAnimator.ofFloat(this.acceptTextView, "scaleY", 1.0f), ObjectAnimator.ofFloat(this.acceptTextView, "alpha", 1.0f));
        }
        this.progressAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.BlockingUpdateView.2
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (BlockingUpdateView.this.progressAnimation != null && BlockingUpdateView.this.progressAnimation.equals(animation)) {
                    if (!show) {
                        BlockingUpdateView.this.radialProgressView.setVisibility(4);
                    } else {
                        BlockingUpdateView.this.acceptTextView.setVisibility(4);
                    }
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (BlockingUpdateView.this.progressAnimation != null && BlockingUpdateView.this.progressAnimation.equals(animation)) {
                    BlockingUpdateView.this.progressAnimation = null;
                }
            }
        });
        this.progressAnimation.setDuration(150L);
        this.progressAnimation.start();
    }

    public void show(int account, TLRPC.TL_help_appUpdate update, boolean check) {
        this.pressCount = 0;
        this.appUpdate = update;
        this.accountNum = account;
        if (update.document instanceof TLRPC.TL_document) {
            this.fileName = FileLoader.getAttachFileName(update.document);
        }
        if (getVisibility() != 0) {
            setVisibility(0);
        }
        SpannableStringBuilder builder = new SpannableStringBuilder(update.text);
        MessageObject.addEntitiesToText(builder, update.entities, false, 0, false, false, false);
        this.textView.setText(builder);
        if (update.document instanceof TLRPC.TL_document) {
            this.acceptTextView.setText(LocaleController.getString("Update", R.string.Update).toUpperCase() + String.format(Locale.US, " (%1$s)", AndroidUtilities.formatFileSize(update.document.size)));
        } else {
            this.acceptTextView.setText(LocaleController.getString("Update", R.string.Update).toUpperCase());
        }
        NotificationCenter.getInstance(this.accountNum).addObserver(this, NotificationCenter.fileDidLoad);
        NotificationCenter.getInstance(this.accountNum).addObserver(this, NotificationCenter.fileDidFailToLoad);
        NotificationCenter.getInstance(this.accountNum).addObserver(this, NotificationCenter.FileLoadProgressChanged);
        if (check) {
            AppUpdater.getInstance(this.accountNum).checkAppUpdate(new AppUpdater.OnForceUpdateCallback() { // from class: im.uwrkaxlmjj.ui.components.BlockingUpdateView.3
                @Override // im.uwrkaxlmjj.ui.utils.AppUpdater.OnForceUpdateCallback
                public void onForce(TLRPC.TL_help_appUpdate res) {
                }

                @Override // im.uwrkaxlmjj.ui.utils.AppUpdater.OnForceUpdateCallback
                public void onNormal(TLRPC.TL_help_appUpdate res) {
                    BlockingUpdateView.this.setVisibility(8);
                    AppUpdater.pendingAppUpdate = null;
                    AppUpdater.getInstance(BlockingUpdateView.this.accountNum).lambda$loadUpdateConfig$2$AppUpdater();
                }

                @Override // im.uwrkaxlmjj.ui.utils.AppUpdater.OnForceUpdateCallback
                public void onNoUpdate() {
                }
            }, true);
        }
    }
}
