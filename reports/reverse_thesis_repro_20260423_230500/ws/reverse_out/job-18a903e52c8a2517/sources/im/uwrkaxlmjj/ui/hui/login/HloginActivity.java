package im.uwrkaxlmjj.ui.hui.login;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Vibrator;
import android.telephony.PhoneNumberUtils;
import android.text.SpannableStringBuilder;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.method.PasswordTransformationMethod;
import android.text.style.ClickableSpan;
import android.util.Base64;
import android.util.Property;
import android.view.KeyEvent;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.AdapterView;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import com.coremedia.iso.boxes.TrackReferenceTypeBox;
import com.google.android.exoplayer2.extractor.ts.TsExtractor;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SRPHelper;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.utils.DrawableUtils;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.CountrySelectActivity;
import im.uwrkaxlmjj.ui.ExternalActionActivity;
import im.uwrkaxlmjj.ui.IndexActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.TwoStepVerificationActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.CheckBoxCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ContextProgressView;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.HintEditText;
import im.uwrkaxlmjj.ui.components.ImageUpdater;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.SlideView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.login.HloginActivity;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import kotlin.text.Typography;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
@Deprecated
public class HloginActivity extends BaseFragment {
    private static final int done_button = 1;
    private boolean checkPermissions;
    private boolean checkShowPermissions;
    private TLRPC.TL_help_termsOfService currentTermsOfService;
    private int currentViewNum;
    private ActionBarMenuItem doneItem;
    private AnimatorSet doneItemAnimation;
    private ContextProgressView doneProgressView;
    private boolean newAccount;
    private Dialog permissionsDialog;
    private ArrayList<String> permissionsItems;
    private Dialog permissionsShowDialog;
    private ArrayList<String> permissionsShowItems;
    private int progressRequestId;
    private int scrollHeight;
    private boolean syncContacts;
    private SlideView[] views;

    private class ProgressView extends View {
        private Paint paint;
        private Paint paint2;
        private float progress;

        public ProgressView(Context context) {
            super(context);
            this.paint = new Paint();
            this.paint2 = new Paint();
            this.paint.setColor(Theme.getColor(Theme.key_login_progressInner));
            this.paint2.setColor(Theme.getColor(Theme.key_login_progressOuter));
        }

        public void setProgress(float value) {
            this.progress = value;
            invalidate();
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            int start = (int) (getMeasuredWidth() * this.progress);
            canvas.drawRect(0.0f, 0.0f, start, getMeasuredHeight(), this.paint2);
            canvas.drawRect(start, 0.0f, getMeasuredWidth(), getMeasuredHeight(), this.paint);
        }
    }

    public HloginActivity() {
        this.views = new SlideView[9];
        this.permissionsItems = new ArrayList<>();
        this.permissionsShowItems = new ArrayList<>();
        this.checkPermissions = true;
        this.checkShowPermissions = true;
        this.syncContacts = true;
    }

    public HloginActivity(int account) {
        this.views = new SlideView[9];
        this.permissionsItems = new ArrayList<>();
        this.permissionsShowItems = new ArrayList<>();
        this.checkPermissions = true;
        this.checkShowPermissions = true;
        this.syncContacts = true;
        this.currentAccount = account;
        this.newAccount = true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        int a = 0;
        while (true) {
            SlideView[] slideViewArr = this.views;
            if (a < slideViewArr.length) {
                if (slideViewArr[a] != null) {
                    slideViewArr[a].onDestroyActivity();
                }
                a++;
            } else {
                return;
            }
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.login.HloginActivity$1, reason: invalid class name */
    class AnonymousClass1 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass1() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            if (id == 1) {
                if (HloginActivity.this.doneProgressView.getTag() == null) {
                    HloginActivity.this.views[HloginActivity.this.currentViewNum].onNextPressed();
                    return;
                }
                if (HloginActivity.this.getParentActivity() == null) {
                    return;
                }
                AlertDialog.Builder builder = new AlertDialog.Builder(HloginActivity.this.getParentActivity());
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setMessage(LocaleController.getString("StopLoading", R.string.StopLoading));
                builder.setPositiveButton(LocaleController.getString("WaitMore", R.string.WaitMore), null);
                builder.setNegativeButton(LocaleController.getString("Stop", R.string.Stop), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$1$YmnLt2O-rCcP7b_pgpXpIX5M2YU
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onItemClick$0$HloginActivity$1(dialogInterface, i);
                    }
                });
                HloginActivity.this.showDialog(builder.create());
                return;
            }
            if (id == -1 && HloginActivity.this.onBackPressed()) {
                HloginActivity.this.finishFragment();
            }
        }

        public /* synthetic */ void lambda$onItemClick$0$HloginActivity$1(DialogInterface dialogInterface, int i) {
            HloginActivity.this.views[HloginActivity.this.currentViewNum].onCancelPressed();
            HloginActivity.this.needHideProgress(true);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass1());
        ActionBarMenu menu = this.actionBar.createMenu();
        Drawable back = getParentActivity().getResources().getDrawable(R.id.ic_login_back).mutate();
        this.actionBar.setBackButtonDrawable(DrawableUtils.tintDrawable(back, Theme.getColor(Theme.key_actionBarDefaultIcon)));
        this.actionBar.setCastShadows(false);
        this.doneItem = menu.addItemWithWidth(1, R.drawable.ic_done, AndroidUtilities.dp(56.0f));
        ContextProgressView contextProgressView = new ContextProgressView(context, 1);
        this.doneProgressView = contextProgressView;
        contextProgressView.setAlpha(0.0f);
        this.doneProgressView.setScaleX(0.1f);
        this.doneProgressView.setScaleY(0.1f);
        this.doneProgressView.setVisibility(4);
        this.doneItem.addView(this.doneProgressView, LayoutHelper.createFrame(-1, -1.0f));
        this.doneItem.setContentDescription(LocaleController.getString("Done", R.string.Done));
        ScrollView scrollView = new ScrollView(context) { // from class: im.uwrkaxlmjj.ui.hui.login.HloginActivity.2
            @Override // android.widget.ScrollView, android.view.ViewGroup, android.view.ViewParent
            public boolean requestChildRectangleOnScreen(View child, Rect rectangle, boolean immediate) {
                if (HloginActivity.this.currentViewNum == 1 || HloginActivity.this.currentViewNum == 2 || HloginActivity.this.currentViewNum == 4) {
                    rectangle.bottom += AndroidUtilities.dp(40.0f);
                }
                return super.requestChildRectangleOnScreen(child, rectangle, immediate);
            }

            @Override // android.widget.ScrollView, android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                HloginActivity.this.scrollHeight = View.MeasureSpec.getSize(heightMeasureSpec) - AndroidUtilities.dp(30.0f);
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            }
        };
        scrollView.setFillViewport(true);
        this.fragmentView = scrollView;
        FrameLayout frameLayout = new FrameLayout(context);
        scrollView.addView(frameLayout, LayoutHelper.createScroll(-1, -2, 51));
        this.views[0] = new PhoneView(context);
        this.views[1] = new LoginActivitySmsView(context, 1);
        this.views[2] = new LoginActivitySmsView(context, 2);
        this.views[3] = new LoginActivitySmsView(context, 3);
        this.views[4] = new LoginActivitySmsView(context, 4);
        this.views[5] = new LoginActivityRegisterView(context);
        this.views[6] = new LoginActivityPasswordView(context);
        this.views[7] = new LoginActivityRecoverView(context);
        this.views[8] = new LoginActivityResetWaitView(context);
        int a = 0;
        while (true) {
            SlideView[] slideViewArr = this.views;
            if (a >= slideViewArr.length) {
                break;
            }
            slideViewArr[a].setVisibility(a == 0 ? 0 : 8);
            SlideView slideView = this.views[a];
            float f = 18.0f;
            float f2 = AndroidUtilities.isTablet() ? 26.0f : 18.0f;
            if (AndroidUtilities.isTablet()) {
                f = 26.0f;
            }
            frameLayout.addView(slideView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, f2, 30.0f, f, 0.0f));
            a++;
        }
        Bundle savedInstanceState = loadCurrentState();
        if (savedInstanceState != null) {
            this.currentViewNum = savedInstanceState.getInt("currentViewNum", 0);
            this.syncContacts = savedInstanceState.getInt("syncContacts", 1) == 1;
            int i = this.currentViewNum;
            if (i < 1 || i > 4) {
                if (this.currentViewNum == 6) {
                    LoginActivityPasswordView view = (LoginActivityPasswordView) this.views[6];
                    if (view.passwordType == 0 || view.current_salt1 == null || view.current_salt2 == null) {
                        this.currentViewNum = 0;
                        savedInstanceState = null;
                        clearCurrentState();
                    }
                }
            } else {
                int time = savedInstanceState.getInt("open");
                if (time != 0 && Math.abs((System.currentTimeMillis() / 1000) - ((long) time)) >= 86400) {
                    this.currentViewNum = 0;
                    savedInstanceState = null;
                    clearCurrentState();
                }
            }
        }
        int a2 = 0;
        while (true) {
            SlideView[] slideViewArr2 = this.views;
            if (a2 < slideViewArr2.length) {
                if (savedInstanceState != null) {
                    if (a2 >= 1 && a2 <= 4) {
                        if (a2 == this.currentViewNum) {
                            slideViewArr2[a2].restoreStateParams(savedInstanceState);
                        }
                    } else {
                        this.views[a2].restoreStateParams(savedInstanceState);
                    }
                }
                if (this.currentViewNum != a2) {
                    this.views[a2].setVisibility(8);
                } else {
                    this.views[a2].setVisibility(0);
                    this.views[a2].onShow();
                    if (a2 == 3 || a2 == 8) {
                        this.doneItem.setVisibility(8);
                    }
                }
                a2++;
            } else {
                return this.fragmentView;
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        AndroidUtilities.removeAdjustResize(getParentActivity(), this.classGuid);
        if (this.newAccount) {
            ConnectionsManager.getInstance(this.currentAccount).setAppPaused(true, false);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        int time;
        super.onResume();
        if (this.newAccount) {
            ConnectionsManager.getInstance(this.currentAccount).setAppPaused(false, false);
        }
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
        try {
            if (this.currentViewNum >= 1 && this.currentViewNum <= 4 && (this.views[this.currentViewNum] instanceof LoginActivitySmsView) && (time = ((LoginActivitySmsView) this.views[this.currentViewNum]).openTime) != 0 && Math.abs((System.currentTimeMillis() / 1000) - ((long) time)) >= 86400) {
                this.views[this.currentViewNum].onBackPressed(true);
                setPage(0, false, null, true);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == 6) {
            this.checkPermissions = false;
            int i = this.currentViewNum;
            if (i == 0) {
                this.views[i].onNextPressed();
                return;
            }
            return;
        }
        if (requestCode == 7) {
            this.checkShowPermissions = false;
            int i2 = this.currentViewNum;
            if (i2 == 0) {
                ((PhoneView) this.views[i2]).fillNumber();
            }
        }
    }

    private Bundle loadCurrentState() {
        if (this.newAccount) {
            return null;
        }
        try {
            Bundle bundle = new Bundle();
            SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("logininfo2", 0);
            Map<String, ?> params = preferences.getAll();
            for (Map.Entry<String, ?> entry : params.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                String[] args = key.split("_\\|_");
                if (args.length == 1) {
                    if (value instanceof String) {
                        bundle.putString(key, (String) value);
                    } else if (value instanceof Integer) {
                        bundle.putInt(key, ((Integer) value).intValue());
                    }
                } else if (args.length == 2) {
                    Bundle inner = bundle.getBundle(args[0]);
                    if (inner == null) {
                        inner = new Bundle();
                        bundle.putBundle(args[0], inner);
                    }
                    if (value instanceof String) {
                        inner.putString(args[1], (String) value);
                    } else if (value instanceof Integer) {
                        inner.putInt(args[1], ((Integer) value).intValue());
                    }
                }
            }
            return bundle;
        } catch (Exception e) {
            FileLog.e(e);
            return null;
        }
    }

    private void clearCurrentState() {
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("logininfo2", 0);
        SharedPreferences.Editor editor = preferences.edit();
        editor.clear();
        editor.commit();
    }

    private void putBundleToEditor(Bundle bundle, SharedPreferences.Editor editor, String prefix) {
        Set<String> keys = bundle.keySet();
        for (String key : keys) {
            Object obj = bundle.get(key);
            if (obj instanceof String) {
                if (prefix != null) {
                    editor.putString(prefix + "_|_" + key, (String) obj);
                } else {
                    editor.putString(key, (String) obj);
                }
            } else if (obj instanceof Integer) {
                if (prefix != null) {
                    editor.putInt(prefix + "_|_" + key, ((Integer) obj).intValue());
                } else {
                    editor.putInt(key, ((Integer) obj).intValue());
                }
            } else if (obj instanceof Bundle) {
                putBundleToEditor((Bundle) obj, editor, key);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onDialogDismiss(Dialog dialog) {
        if (Build.VERSION.SDK_INT >= 23) {
            if (dialog == this.permissionsDialog && !this.permissionsItems.isEmpty() && getParentActivity() != null) {
                try {
                    getParentActivity().requestPermissions((String[]) this.permissionsItems.toArray(new String[0]), 6);
                } catch (Exception e) {
                }
            } else if (dialog == this.permissionsShowDialog && !this.permissionsShowItems.isEmpty() && getParentActivity() != null) {
                try {
                    getParentActivity().requestPermissions((String[]) this.permissionsShowItems.toArray(new String[0]), 7);
                } catch (Exception e2) {
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        int i = this.currentViewNum;
        if (i == 0) {
            int a = 0;
            while (true) {
                SlideView[] slideViewArr = this.views;
                if (a < slideViewArr.length) {
                    if (slideViewArr[a] != null) {
                        slideViewArr[a].onDestroyActivity();
                    }
                    a++;
                } else {
                    clearCurrentState();
                    return true;
                }
            }
        } else {
            if (i == 6) {
                this.views[i].onBackPressed(true);
                setPage(0, true, null, true);
            } else if (i == 7 || i == 8) {
                this.views[this.currentViewNum].onBackPressed(true);
                setPage(6, true, null, true);
            } else if (i >= 1 && i <= 4) {
                if (this.views[i].onBackPressed(false)) {
                    setPage(0, true, null, true);
                }
            } else {
                int i2 = this.currentViewNum;
                if (i2 == 5) {
                    ((LoginActivityRegisterView) this.views[i2]).wrongNumber.callOnClick();
                }
            }
            return false;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) throws FileNotFoundException {
        LoginActivityRegisterView registerView = (LoginActivityRegisterView) this.views[5];
        if (registerView == null) {
            return;
        }
        registerView.imageUpdater.onActivityResult(requestCode, resultCode, data);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void needShowAlert(String title, String text) {
        if (text == null || getParentActivity() == null) {
            return;
        }
        XDialog.Builder builder = new XDialog.Builder(getParentActivity());
        builder.setTitle(title);
        builder.setMessage(text);
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        showDialog(builder.create());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void needShowInvalidAlert(final String phoneNumber, final boolean banned) {
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        if (banned) {
            builder.setMessage(LocaleController.getString("BannedPhoneNumber", R.string.BannedPhoneNumber));
        } else {
            builder.setMessage(LocaleController.getString("InvalidPhoneNumber", R.string.InvalidPhoneNumber));
        }
        builder.setNeutralButton(LocaleController.getString("BotHelp", R.string.BotHelp), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$ZloE_dDuhgtMYMoRb6qBMIHsKh0
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$needShowInvalidAlert$0$HloginActivity(banned, phoneNumber, dialogInterface, i);
            }
        });
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$needShowInvalidAlert$0$HloginActivity(boolean banned, String phoneNumber, DialogInterface dialog, int which) {
        try {
            PackageInfo pInfo = ApplicationLoader.applicationContext.getPackageManager().getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0);
            String version = String.format(Locale.US, "%s (%d)", pInfo.versionName, Integer.valueOf(pInfo.versionCode));
            Intent mailer = new Intent("android.intent.action.SEND");
            mailer.setType("message/rfc822");
            mailer.putExtra("android.intent.extra.EMAIL", new String[]{"login@stel.com"});
            if (banned) {
                mailer.putExtra("android.intent.extra.SUBJECT", "Banned phone number: " + phoneNumber);
                mailer.putExtra("android.intent.extra.TEXT", "I'm trying to use my mobile phone number: " + phoneNumber + "\nBut App says it's banned. Please help.\n\nApp version: " + version + "\nOS version: SDK " + Build.VERSION.SDK_INT + "\nDevice Name: " + Build.MANUFACTURER + Build.MODEL + "\nLocale: " + Locale.getDefault());
            } else {
                mailer.putExtra("android.intent.extra.SUBJECT", "Invalid phone number: " + phoneNumber);
                mailer.putExtra("android.intent.extra.TEXT", "I'm trying to use my mobile phone number: " + phoneNumber + "\nBut App says it's invalid. Please help.\n\nApp version: " + version + "\nOS version: SDK " + Build.VERSION.SDK_INT + "\nDevice Name: " + Build.MANUFACTURER + Build.MODEL + "\nLocale: " + Locale.getDefault());
            }
            getParentActivity().startActivity(Intent.createChooser(mailer, "Send email..."));
        } catch (Exception e) {
            needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("NoMailInstalled", R.string.NoMailInstalled));
        }
    }

    private void showEditDoneProgress(final boolean show) {
        AnimatorSet animatorSet = this.doneItemAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.doneItemAnimation = new AnimatorSet();
        if (show) {
            this.doneProgressView.setTag(1);
            this.doneProgressView.setVisibility(0);
            this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.doneProgressView, (Property<ContextProgressView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.doneProgressView, (Property<ContextProgressView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.doneProgressView, (Property<ContextProgressView, Float>) View.ALPHA, 1.0f));
        } else {
            this.doneProgressView.setTag(null);
            this.doneItem.getContentView().setVisibility(0);
            this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.doneProgressView, (Property<ContextProgressView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.doneProgressView, (Property<ContextProgressView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.doneProgressView, (Property<ContextProgressView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.ALPHA, 1.0f));
        }
        this.doneItemAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.login.HloginActivity.3
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (HloginActivity.this.doneItemAnimation != null && HloginActivity.this.doneItemAnimation.equals(animation)) {
                    if (!show) {
                        HloginActivity.this.doneProgressView.setVisibility(4);
                    } else {
                        HloginActivity.this.doneItem.getContentView().setVisibility(4);
                    }
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (HloginActivity.this.doneItemAnimation != null && HloginActivity.this.doneItemAnimation.equals(animation)) {
                    HloginActivity.this.doneItemAnimation = null;
                }
            }
        });
        this.doneItemAnimation.setDuration(150L);
        this.doneItemAnimation.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void needShowProgress(int reqiestId) {
        this.progressRequestId = reqiestId;
        showEditDoneProgress(true);
    }

    public void needHideProgress(boolean cancel) {
        if (this.progressRequestId != 0) {
            if (cancel) {
                ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.progressRequestId, true);
            }
            this.progressRequestId = 0;
        }
        showEditDoneProgress(false);
    }

    public void setPage(int page, boolean animated, Bundle params, boolean back) {
        if (page == 3 || page == 8) {
            this.doneItem.setVisibility(8);
        } else {
            if (page == 0) {
                this.checkPermissions = true;
                this.checkShowPermissions = true;
            }
            this.doneItem.setVisibility(0);
        }
        int i = this.currentViewNum;
        if (i == page) {
            this.views[i].setParams(params, false);
            return;
        }
        if (animated) {
            SlideView[] slideViewArr = this.views;
            final SlideView outView = slideViewArr[i];
            SlideView newView = slideViewArr[page];
            this.currentViewNum = page;
            newView.setParams(params, false);
            setParentActivityTitle(newView.getHeaderName());
            newView.onShow();
            int i2 = AndroidUtilities.displaySize.x;
            if (back) {
                i2 = -i2;
            }
            newView.setX(i2);
            newView.setVisibility(0);
            AnimatorSet animatorSet = new AnimatorSet();
            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.login.HloginActivity.4
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    outView.setVisibility(8);
                    outView.setX(0.0f);
                }
            });
            Animator[] animatorArr = new Animator[2];
            Property property = View.TRANSLATION_X;
            float[] fArr = new float[1];
            int i3 = AndroidUtilities.displaySize.x;
            if (!back) {
                i3 = -i3;
            }
            fArr[0] = i3;
            animatorArr[0] = ObjectAnimator.ofFloat(outView, (Property<SlideView, Float>) property, fArr);
            animatorArr[1] = ObjectAnimator.ofFloat(newView, (Property<SlideView, Float>) View.TRANSLATION_X, 0.0f);
            animatorSet.playTogether(animatorArr);
            animatorSet.setDuration(300L);
            animatorSet.setInterpolator(new AccelerateDecelerateInterpolator());
            animatorSet.start();
            return;
        }
        this.actionBar.setBackButtonImage((this.views[page].needBackButton() || this.newAccount) ? R.id.ic_back : 0);
        this.views[this.currentViewNum].setVisibility(8);
        this.currentViewNum = page;
        this.views[page].setParams(params, false);
        this.views[page].setVisibility(0);
        setParentActivityTitle(this.views[page].getHeaderName());
        this.views[page].onShow();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle outState) {
        try {
            Bundle bundle = new Bundle();
            bundle.putInt("currentViewNum", this.currentViewNum);
            bundle.putInt("syncContacts", this.syncContacts ? 1 : 0);
            for (int a = 0; a <= this.currentViewNum; a++) {
                SlideView v = this.views[a];
                if (v != null) {
                    v.saveStateParams(bundle);
                }
            }
            SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("logininfo2", 0);
            SharedPreferences.Editor editor = preferences.edit();
            editor.clear();
            putBundleToEditor(bundle, editor, null);
            editor.commit();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private void needFinishActivity() {
        clearCurrentState();
        if (getParentActivity() instanceof LaunchActivity) {
            if (this.newAccount) {
                this.newAccount = false;
                ((LaunchActivity) getParentActivity()).switchToAccount(this.currentAccount, true);
                finishFragment();
                return;
            } else {
                presentFragment(new IndexActivity(), true);
                NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
                return;
            }
        }
        if (getParentActivity() instanceof ExternalActionActivity) {
            ((ExternalActionActivity) getParentActivity()).onFinishLogin();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onAuthSuccess(TLRPC.TL_auth_authorization res) {
        ConnectionsManager.getInstance(this.currentAccount).setUserId(res.user.id);
        UserConfig.getInstance(this.currentAccount).clearConfig();
        MessagesController.getInstance(this.currentAccount).cleanup();
        UserConfig.getInstance(this.currentAccount).syncContacts = this.syncContacts;
        UserConfig.getInstance(this.currentAccount).setCurrentUser(res.user);
        UserConfig.getInstance(this.currentAccount).saveConfig(true);
        MessagesStorage.getInstance(this.currentAccount).cleanup(true);
        ArrayList<TLRPC.User> users = new ArrayList<>();
        users.add(res.user);
        MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(users, null, true, true);
        MessagesController.getInstance(this.currentAccount).putUser(res.user, false);
        ContactsController.getInstance(this.currentAccount).checkAppAccount();
        MessagesController.getInstance(this.currentAccount).checkProxyInfo(true);
        ConnectionsManager.getInstance(this.currentAccount).updateDcSettings();
        needFinishActivity();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fillNextCodeParams(Bundle params, TLRPC.TL_auth_sentCode res) {
        params.putString("phoneHash", res.phone_code_hash);
        if (res.next_type instanceof TLRPC.TL_auth_codeTypeCall) {
            params.putInt("nextType", 4);
        } else if (res.next_type instanceof TLRPC.TL_auth_codeTypeFlashCall) {
            params.putInt("nextType", 3);
        } else if (res.next_type instanceof TLRPC.TL_auth_codeTypeSms) {
            params.putInt("nextType", 2);
        }
        if (res.type instanceof TLRPC.TL_auth_sentCodeTypeApp) {
            params.putInt("type", 1);
            params.putInt("length", res.type.length);
            setPage(1, true, params, false);
            return;
        }
        if (res.timeout == 0) {
            res.timeout = 60;
        }
        params.putInt("timeout", res.timeout * 1000);
        if (res.type instanceof TLRPC.TL_auth_sentCodeTypeCall) {
            params.putInt("type", 4);
            params.putInt("length", res.type.length);
            setPage(4, true, params, false);
        } else if (res.type instanceof TLRPC.TL_auth_sentCodeTypeFlashCall) {
            params.putInt("type", 3);
            params.putString("pattern", res.type.pattern);
            setPage(3, true, params, false);
        } else if (res.type instanceof TLRPC.TL_auth_sentCodeTypeSms) {
            params.putInt("type", 2);
            params.putInt("length", res.type.length);
            setPage(2, true, params, false);
        }
    }

    public class PhoneView extends SlideView implements AdapterView.OnItemSelectedListener {
        private CheckBoxCell checkBoxCell;
        private EditTextBoldCursor codeField;
        private HashMap<String, String> codesMap;
        private ArrayList<String> countriesArray;
        private HashMap<String, String> countriesMap;
        private TextView countryButton;
        private int countryState;
        private boolean ignoreOnPhoneChange;
        private boolean ignoreOnTextChange;
        private boolean ignoreSelection;
        private boolean nextPressed;
        private HintEditText phoneField;
        private HashMap<String, String> phoneFormatMap;
        private TextView textView;
        private TextView textView2;
        private View view;

        /* JADX WARN: Can't wrap try/catch for region: R(22:0|2|(1:4)(1:5)|6|(1:8)(1:9)|10|(1:12)(1:13)|14|(1:16)|17|(2:49|18)|(11:19|(3:21|(2:23|52)(1:53)|24)(1:51)|29|47|30|(1:32)|(1:37)(1:38)|39|(1:41)|42|(2:44|54)(2:45|46))|25|29|47|30|(0)|(0)(0)|39|(0)|42|(0)(0)) */
        /* JADX WARN: Code restructure failed: missing block: B:34:0x0520, code lost:
        
            r0 = move-exception;
         */
        /* JADX WARN: Code restructure failed: missing block: B:35:0x0521, code lost:
        
            im.uwrkaxlmjj.messenger.FileLog.e(r0);
         */
        /* JADX WARN: Removed duplicated region for block: B:32:0x051e  */
        /* JADX WARN: Removed duplicated region for block: B:37:0x0526  */
        /* JADX WARN: Removed duplicated region for block: B:38:0x052e  */
        /* JADX WARN: Removed duplicated region for block: B:41:0x054d  */
        /* JADX WARN: Removed duplicated region for block: B:44:0x056c  */
        /* JADX WARN: Removed duplicated region for block: B:45:0x057b  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public PhoneView(android.content.Context r45) {
            /*
                Method dump skipped, instruction units count: 1409
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.login.HloginActivity.PhoneView.<init>(im.uwrkaxlmjj.ui.hui.login.HloginActivity, android.content.Context):void");
        }

        public /* synthetic */ void lambda$new$2$HloginActivity$PhoneView(View view) {
            CountrySelectActivity fragment = new CountrySelectActivity(true);
            fragment.setCountrySelectActivityDelegate(new CountrySelectActivity.CountrySelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$PhoneView$H_oVaeQl95rwPuMRgCUQSPcqqx8
                @Override // im.uwrkaxlmjj.ui.CountrySelectActivity.CountrySelectActivityDelegate
                public final void didSelectCountry(CountrySelectActivity.Country country) {
                    this.f$0.lambda$null$1$HloginActivity$PhoneView(country);
                }
            });
            HloginActivity.this.presentFragment(fragment);
        }

        public /* synthetic */ void lambda$null$1$HloginActivity$PhoneView(CountrySelectActivity.Country country) {
            selectCountry(null, country);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$PhoneView$vciKiHWgEAjY765vn6sZMb11270
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$HloginActivity$PhoneView();
                }
            }, 300L);
            this.phoneField.requestFocus();
            HintEditText hintEditText = this.phoneField;
            hintEditText.setSelection(hintEditText.length());
        }

        public /* synthetic */ void lambda$null$0$HloginActivity$PhoneView() {
            AndroidUtilities.showKeyboard(this.phoneField);
        }

        public /* synthetic */ boolean lambda$new$3$HloginActivity$PhoneView(TextView textView, int i, KeyEvent keyEvent) {
            if (i == 5) {
                this.phoneField.requestFocus();
                HintEditText hintEditText = this.phoneField;
                hintEditText.setSelection(hintEditText.length());
                return true;
            }
            return false;
        }

        public /* synthetic */ boolean lambda$new$4$HloginActivity$PhoneView(TextView textView, int i, KeyEvent keyEvent) {
            if (i == 5) {
                onNextPressed();
                return true;
            }
            return false;
        }

        public /* synthetic */ boolean lambda$new$5$HloginActivity$PhoneView(View v, int keyCode, KeyEvent event) {
            if (keyCode == 67 && this.phoneField.length() == 0) {
                this.codeField.requestFocus();
                EditTextBoldCursor editTextBoldCursor = this.codeField;
                editTextBoldCursor.setSelection(editTextBoldCursor.length());
                this.codeField.dispatchKeyEvent(event);
                return true;
            }
            return false;
        }

        public /* synthetic */ void lambda$new$6$HloginActivity$PhoneView(View v) {
            onNextPressed();
        }

        public /* synthetic */ void lambda$new$7$HloginActivity$PhoneView(View v) {
            if (HloginActivity.this.getParentActivity() == null) {
                return;
            }
            CheckBoxCell cell = (CheckBoxCell) v;
            HloginActivity.this.syncContacts = !r1.syncContacts;
            cell.setChecked(HloginActivity.this.syncContacts, true);
            if (HloginActivity.this.syncContacts) {
                ToastUtils.show(R.string.SyncContactsOn);
            } else {
                ToastUtils.show(R.string.SyncContactsOff);
            }
        }

        public /* synthetic */ void lambda$new$9$HloginActivity$PhoneView(final HashMap languageMap, final TLObject response, TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$PhoneView$oDSf7CHM6HfnrdugYFKt5M_fR0c
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$8$HloginActivity$PhoneView(response, languageMap);
                }
            });
        }

        public /* synthetic */ void lambda$null$8$HloginActivity$PhoneView(TLObject response, HashMap languageMap) {
            if (response == null) {
                return;
            }
            TLRPC.TL_nearestDc res = (TLRPC.TL_nearestDc) response;
            if (this.codeField.length() == 0) {
                setCountry(languageMap, res.country.toUpperCase());
            }
        }

        public void selectCountry(String name, CountrySelectActivity.Country country) {
            if (name != null) {
                int index = this.countriesArray.indexOf(name);
                if (index != -1) {
                    this.ignoreOnTextChange = true;
                    String code = this.countriesMap.get(name);
                    this.codeField.setText(code);
                    this.countryButton.setText(name);
                    String hint = this.phoneFormatMap.get(code);
                    this.phoneField.setHintText(hint != null ? hint.replace('X', Typography.ndash) : null);
                    this.countryState = 0;
                    this.ignoreOnTextChange = false;
                    return;
                }
                return;
            }
            if (country != null) {
                this.ignoreOnTextChange = true;
                this.codeField.setText(country.code + "");
                if (country.phoneFormat != null) {
                    this.phoneField.setHintText(country.phoneFormat != null ? country.phoneFormat.replace('X', Typography.ndash) : null);
                }
                this.countryState = 0;
                this.ignoreOnTextChange = false;
            }
        }

        private void setCountry(HashMap<String, String> languageMap, String country) {
            String countryName = languageMap.get(country);
            if (countryName != null) {
                int index = this.countriesArray.indexOf(countryName);
                if (index != -1) {
                    this.codeField.setText(this.countriesMap.get(countryName));
                    this.countryState = 0;
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onCancelPressed() {
            this.nextPressed = false;
        }

        @Override // android.widget.AdapterView.OnItemSelectedListener
        public void onItemSelected(AdapterView<?> adapterView, View view, int i, long l) {
            if (this.ignoreSelection) {
                this.ignoreSelection = false;
                return;
            }
            this.ignoreOnTextChange = true;
            String str = this.countriesArray.get(i);
            this.codeField.setText(this.countriesMap.get(str));
            this.ignoreOnTextChange = false;
        }

        @Override // android.widget.AdapterView.OnItemSelectedListener
        public void onNothingSelected(AdapterView<?> adapterView) {
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onNextPressed() {
            if (HloginActivity.this.getParentActivity() == null || this.nextPressed) {
                return;
            }
            int i = this.countryState;
            if (i == 1) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("ChooseCountry", R.string.ChooseCountry));
                return;
            }
            if (i == 2 && !BuildVars.DEBUG_VERSION) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("WrongCountry", R.string.WrongCountry));
                return;
            }
            if (this.codeField.length() == 0) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("InvalidPhoneNumber", R.string.InvalidPhoneNumber));
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append(PhoneFormat.stripExceptNumbers("" + ((Object) this.codeField.getText())));
            sb.append(" ");
            sb.append(PhoneFormat.stripExceptNumbers("" + ((Object) this.phoneField.getText())));
            String phone = sb.toString();
            if (HloginActivity.this.getParentActivity() instanceof LaunchActivity) {
                for (int a = 0; a < 3; a++) {
                    UserConfig userConfig = UserConfig.getInstance(a);
                    if (userConfig.isClientActivated()) {
                        String userPhone = userConfig.getCurrentUser().phone;
                        if (PhoneNumberUtils.compare(phone, userPhone)) {
                            final int num = a;
                            AlertDialog.Builder builder = new AlertDialog.Builder(HloginActivity.this.getParentActivity());
                            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                            builder.setMessage(LocaleController.getString("AccountAlreadyLoggedIn", R.string.AccountAlreadyLoggedIn));
                            builder.setPositiveButton(LocaleController.getString("AccountSwitch", R.string.AccountSwitch), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$PhoneView$g0FbJspVQtRu9vu52TGmKZgHBRc
                                @Override // android.content.DialogInterface.OnClickListener
                                public final void onClick(DialogInterface dialogInterface, int i2) {
                                    this.f$0.lambda$onNextPressed$10$HloginActivity$PhoneView(num, dialogInterface, i2);
                                }
                            });
                            builder.setNegativeButton(LocaleController.getString("OK", R.string.OK), null);
                            HloginActivity.this.showDialog(builder.create());
                            return;
                        }
                    }
                }
            }
            ConnectionsManager.getInstance(HloginActivity.this.currentAccount).cleanup(false);
            final TLRPC.TL_auth_sendCode req = new TLRPC.TL_auth_sendCode();
            req.api_hash = BuildVars.APP_HASH;
            req.api_id = BuildVars.APP_ID;
            req.phone_number = phone;
            req.settings = new TLRPC.TL_codeSettings();
            req.settings.allow_flashcall = false;
            req.settings.allow_app_hash = ApplicationLoader.hasPlayServices;
            SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", 0);
            if (req.settings.allow_app_hash) {
                preferences.edit().putString("sms_hash", BuildVars.SMS_HASH).commit();
            } else {
                preferences.edit().remove("sms_hash").commit();
            }
            final Bundle params = new Bundle();
            params.putString("phone", Marker.ANY_NON_NULL_MARKER + ((Object) this.codeField.getText()) + " " + ((Object) this.phoneField.getText()));
            try {
                params.putString("ephone", Marker.ANY_NON_NULL_MARKER + PhoneFormat.stripExceptNumbers(this.codeField.getText().toString()) + " " + PhoneFormat.stripExceptNumbers(this.phoneField.getText().toString()));
            } catch (Exception e) {
                FileLog.e(e);
                params.putString("ephone", Marker.ANY_NON_NULL_MARKER + phone);
            }
            params.putString("phoneFormated", phone);
            this.nextPressed = true;
            int reqId = ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$PhoneView$YOGGQMm4ffRsWOup5OcfxflU4kI
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$onNextPressed$12$HloginActivity$PhoneView(params, req, tLObject, tL_error);
                }
            }, 27);
            HloginActivity.this.needShowProgress(reqId);
        }

        public /* synthetic */ void lambda$onNextPressed$10$HloginActivity$PhoneView(int num, DialogInterface dialog, int which) {
            if (UserConfig.selectedAccount != num) {
                ((LaunchActivity) HloginActivity.this.getParentActivity()).switchToAccount(num, false);
            }
            HloginActivity.this.finishFragment();
        }

        public /* synthetic */ void lambda$onNextPressed$12$HloginActivity$PhoneView(final Bundle params, final TLRPC.TL_auth_sendCode req, final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$PhoneView$FrNNYiUsSu07A7ej-ZBQ54Y6arw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$11$HloginActivity$PhoneView(error, params, response, req);
                }
            });
        }

        public /* synthetic */ void lambda$null$11$HloginActivity$PhoneView(TLRPC.TL_error error, Bundle params, TLObject response, TLRPC.TL_auth_sendCode req) {
            this.nextPressed = false;
            if (error == null) {
                HloginActivity.this.fillNextCodeParams(params, (TLRPC.TL_auth_sentCode) response);
            } else if (error.text != null) {
                if (error.text.contains("PHONE_NUMBER_INVALID")) {
                    HloginActivity.this.needShowInvalidAlert(req.phone_number, false);
                } else if (error.text.contains("PHONE_PASSWORD_FLOOD")) {
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("FloodWait", R.string.FloodWait));
                } else if (error.text.contains("PHONE_NUMBER_FLOOD")) {
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("PhoneNumberFlood", R.string.PhoneNumberFlood));
                } else if (error.text.contains("PHONE_NUMBER_BANNED")) {
                    HloginActivity.this.needShowInvalidAlert(req.phone_number, true);
                } else if (error.text.contains("PHONE_CODE_EMPTY") || error.text.contains("PHONE_CODE_INVALID")) {
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("InvalidCode", R.string.InvalidCode));
                } else if (error.text.contains("PHONE_CODE_EXPIRED")) {
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("CodeExpired", R.string.CodeExpired));
                } else if (error.text.startsWith("FLOOD_WAIT")) {
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("FloodWait", R.string.FloodWait));
                } else if (error.code != -1000) {
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), error.text);
                }
            }
            HloginActivity.this.needHideProgress(false);
        }

        public void fillNumber() {
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onShow() {
            super.onShow();
            fillNumber();
            CheckBoxCell checkBoxCell = this.checkBoxCell;
            if (checkBoxCell != null) {
                checkBoxCell.setChecked(HloginActivity.this.syncContacts, false);
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$PhoneView$BqpT1mTN4dr6QcOVRkjliPrxPeY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onShow$13$HloginActivity$PhoneView();
                }
            }, 100L);
        }

        public /* synthetic */ void lambda$onShow$13$HloginActivity$PhoneView() {
            if (this.phoneField != null) {
                if (this.codeField.length() != 0) {
                    this.phoneField.requestFocus();
                    HintEditText hintEditText = this.phoneField;
                    hintEditText.setSelection(hintEditText.length());
                    AndroidUtilities.showKeyboard(this.phoneField);
                    return;
                }
                this.codeField.requestFocus();
                AndroidUtilities.showKeyboard(this.codeField);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public String getHeaderName() {
            return LocaleController.getString("YourPhone", R.string.YourPhone);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void saveStateParams(Bundle bundle) {
            String code = this.codeField.getText().toString();
            if (code.length() != 0) {
                bundle.putString("phoneview_code", code);
            }
            String phone = this.phoneField.getText().toString();
            if (phone.length() != 0) {
                bundle.putString("phoneview_phone", phone);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void restoreStateParams(Bundle bundle) {
            String code = bundle.getString("phoneview_code");
            if (code != null) {
                this.codeField.setText(code);
            }
            String phone = bundle.getString("phoneview_phone");
            if (phone != null) {
                this.phoneField.setText(phone);
            }
        }
    }

    public class LoginActivitySmsView extends SlideView implements NotificationCenter.NotificationCenterDelegate {
        private ImageView blackImageView;
        private ImageView blueImageView;
        private String catchedPhone;
        private EditTextBoldCursor[] codeField;
        private LinearLayout codeFieldContainer;
        private int codeTime;
        private Timer codeTimer;
        private TextView confirmTextView;
        private Bundle currentParams;
        private int currentType;
        private String emailPhone;
        private boolean ignoreOnTextChange;
        private boolean isRestored;
        private double lastCodeTime;
        private double lastCurrentTime;
        private String lastError;
        private int length;
        private boolean nextPressed;
        private int nextType;
        private int openTime;
        private String pattern;
        private String phone;
        private String phoneHash;
        private TextView problemText;
        private ProgressView progressView;
        private String requestPhone;
        private int time;
        private TextView timeText;
        private Timer timeTimer;
        private int timeout;
        private final Object timerSync;
        private TextView titleTextView;
        private boolean waitingForEvent;

        public LoginActivitySmsView(Context context, int type) {
            super(context);
            this.timerSync = new Object();
            this.time = 60000;
            this.codeTime = 15000;
            this.lastError = "";
            this.pattern = "*";
            this.currentType = type;
            setOrientation(1);
            TextView textView = new TextView(context);
            this.confirmTextView = textView;
            textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.confirmTextView.setTextSize(1, 14.0f);
            this.confirmTextView.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            TextView textView2 = new TextView(context);
            this.titleTextView = textView2;
            textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.titleTextView.setTextSize(1, 18.0f);
            this.titleTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.titleTextView.setGravity(LocaleController.isRTL ? 5 : 3);
            this.titleTextView.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            this.titleTextView.setGravity(49);
            if (this.currentType == 3) {
                this.confirmTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
                FrameLayout frameLayout = new FrameLayout(context);
                addView(frameLayout, LayoutHelper.createLinear(-2, -2, LocaleController.isRTL ? 5 : 3));
                ImageView imageView = new ImageView(context);
                imageView.setImageResource(R.drawable.phone_activate);
                if (LocaleController.isRTL) {
                    frameLayout.addView(imageView, LayoutHelper.createFrame(64.0f, 76.0f, 19, 2.0f, 2.0f, 0.0f, 0.0f));
                    frameLayout.addView(this.confirmTextView, LayoutHelper.createFrame(-1.0f, -2.0f, LocaleController.isRTL ? 5 : 3, 82.0f, 0.0f, 0.0f, 0.0f));
                } else {
                    frameLayout.addView(this.confirmTextView, LayoutHelper.createFrame(-1.0f, -2.0f, LocaleController.isRTL ? 5 : 3, 0.0f, 0.0f, 82.0f, 0.0f));
                    frameLayout.addView(imageView, LayoutHelper.createFrame(64.0f, 76.0f, 21, 0.0f, 2.0f, 0.0f, 2.0f));
                }
            } else {
                this.confirmTextView.setGravity(49);
                FrameLayout frameLayout2 = new FrameLayout(context);
                addView(frameLayout2, LayoutHelper.createLinear(-2, -2, 49));
                if (this.currentType == 1) {
                    ImageView imageView2 = new ImageView(context);
                    this.blackImageView = imageView2;
                    imageView2.setImageResource(R.drawable.sms_devices);
                    this.blackImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText), PorterDuff.Mode.MULTIPLY));
                    frameLayout2.addView(this.blackImageView, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 0.0f, 0.0f, 0.0f, 0.0f));
                    ImageView imageView3 = new ImageView(context);
                    this.blueImageView = imageView3;
                    imageView3.setImageResource(R.drawable.sms_bubble);
                    this.blueImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chats_actionBackground), PorterDuff.Mode.MULTIPLY));
                    frameLayout2.addView(this.blueImageView, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 0.0f, 0.0f, 0.0f, 0.0f));
                    this.titleTextView.setText(LocaleController.getString("SentAppCodeTitle", R.string.SentAppCodeTitle));
                } else {
                    this.titleTextView.setText(LocaleController.getString("SentSmsCodeTitle", R.string.SentSmsCodeTitle));
                }
                addView(this.titleTextView, LayoutHelper.createLinear(-2, -2, 49, 0, 18, 0, 0));
                addView(this.confirmTextView, LayoutHelper.createLinear(-2, -2, 49, 0, 17, 0, 0));
            }
            View view = new View(context);
            view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayLine));
            addView(view, LayoutHelper.createLinear(-1.0f, 0.5f, 16, 16.0f, 72.0f, 16.0f, 0.0f));
            LinearLayout container = new LinearLayout(context);
            container.setOrientation(0);
            addView(container, LayoutHelper.createLinear(-1, 68, 1, 16, 0, 16, 0));
            ImageView iconVertifyCode = new ImageView(context);
            iconVertifyCode.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
            Drawable phoneVertify = HloginActivity.this.getParentActivity().getResources().getDrawable(R.id.icon_phone).mutate();
            iconVertifyCode.setImageDrawable(DrawableUtils.tintDrawable(phoneVertify, Theme.getColor(Theme.key_actionBarDefaultIcon)));
            container.addView(iconVertifyCode, LayoutHelper.createLinear(-2, -2, 16));
            View view2 = new View(context);
            view2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayLine));
            container.addView(view2, LayoutHelper.createLinear(0.5f, 34.0f, 16, 16.0f, 0.0f, 16.0f, 0.0f));
            LinearLayout linearLayout = new LinearLayout(context);
            this.codeFieldContainer = linearLayout;
            linearLayout.setOrientation(0);
            container.addView(this.codeFieldContainer, LayoutHelper.createLinear(-2, 34, 16, 0, 0, 0, 0));
            if (this.currentType == 3) {
                this.codeFieldContainer.setVisibility(8);
            }
            View view3 = new View(context);
            view3.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayLine));
            addView(view3, LayoutHelper.createLinear(-1.0f, 0.5f, 16, 16.0f, 0.0f, 16.0f, 0.0f));
            TextView textView3 = new TextView(context) { // from class: im.uwrkaxlmjj.ui.hui.login.HloginActivity.LoginActivitySmsView.1
                @Override // android.widget.TextView, android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(100.0f), Integer.MIN_VALUE));
                }
            };
            this.timeText = textView3;
            textView3.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.timeText.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            if (this.currentType == 3) {
                this.timeText.setTextSize(1, 14.0f);
                addView(this.timeText, LayoutHelper.createLinear(-2, -2, LocaleController.isRTL ? 5 : 3));
                this.progressView = HloginActivity.this.new ProgressView(context);
                this.timeText.setGravity(LocaleController.isRTL ? 5 : 3);
                addView(this.progressView, LayoutHelper.createLinear(-1, 3, 0.0f, 12.0f, 0.0f, 0.0f));
            } else {
                this.timeText.setPadding(0, AndroidUtilities.dp(2.0f), 0, AndroidUtilities.dp(10.0f));
                this.timeText.setTextSize(1, 15.0f);
                this.timeText.setGravity(49);
                addView(this.timeText, LayoutHelper.createLinear(-2, -2, 49));
            }
            TextView textView4 = new TextView(context) { // from class: im.uwrkaxlmjj.ui.hui.login.HloginActivity.LoginActivitySmsView.2
                @Override // android.widget.TextView, android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(100.0f), Integer.MIN_VALUE));
                }
            };
            this.problemText = textView4;
            textView4.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText4));
            this.problemText.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            this.problemText.setPadding(0, AndroidUtilities.dp(2.0f), 0, AndroidUtilities.dp(10.0f));
            this.problemText.setTextSize(1, 15.0f);
            this.problemText.setGravity(49);
            if (this.currentType == 1) {
                this.problemText.setText(LocaleController.getString("DidNotGetTheCodeSms", R.string.DidNotGetTheCodeSms));
            } else {
                this.problemText.setText(LocaleController.getString("DidNotGetTheCode", R.string.DidNotGetTheCode));
            }
            addView(this.problemText, LayoutHelper.createLinear(-2, -2, 49, 0, 50, 0, 0));
            this.problemText.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$JG-79czvgOUxxViALSqwjEfxDXA
                @Override // android.view.View.OnClickListener
                public final void onClick(View view4) {
                    this.f$0.lambda$new$0$HloginActivity$LoginActivitySmsView(view4);
                }
            });
            TextView startMessagingButton = new TextView(context);
            startMessagingButton.setText(LocaleController.getString("Next", R.string.Next).toUpperCase());
            startMessagingButton.setGravity(17);
            startMessagingButton.setTextColor(-1);
            startMessagingButton.setTextSize(1, 16.0f);
            startMessagingButton.setBackground(Theme.createSimpleSelectorRoundRectDrawable(AndroidUtilities.dp(24.0f), Color.parseColor("#FF268CFF"), Color.parseColor("#FF1E69BD")));
            if (Build.VERSION.SDK_INT >= 21) {
                StateListAnimator animator = new StateListAnimator();
                animator.addState(new int[]{android.R.attr.state_pressed}, ObjectAnimator.ofFloat(startMessagingButton, "translationZ", AndroidUtilities.dp(2.0f), AndroidUtilities.dp(4.0f)).setDuration(200L));
                animator.addState(new int[0], ObjectAnimator.ofFloat(startMessagingButton, "translationZ", AndroidUtilities.dp(4.0f), AndroidUtilities.dp(2.0f)).setDuration(200L));
                startMessagingButton.setStateListAnimator(animator);
            }
            startMessagingButton.setPadding(AndroidUtilities.dp(20.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(20.0f), AndroidUtilities.dp(10.0f));
            addView(startMessagingButton, LayoutHelper.createLinear(-1, -2, 17, 32, 50, 32, 0));
            startMessagingButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$ALqjrk-Q3ya9SOYYUWp1zWMQJME
                @Override // android.view.View.OnClickListener
                public final void onClick(View view4) {
                    this.f$0.lambda$new$1$HloginActivity$LoginActivitySmsView(view4);
                }
            });
        }

        public /* synthetic */ void lambda$new$0$HloginActivity$LoginActivitySmsView(View v) {
            if (this.nextPressed) {
                return;
            }
            boolean email = (this.nextType == 4 && this.currentType == 2) || this.nextType == 0;
            if (!email) {
                if (HloginActivity.this.doneProgressView.getTag() != null) {
                    return;
                }
                resendCode();
                return;
            }
            try {
                PackageInfo pInfo = ApplicationLoader.applicationContext.getPackageManager().getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0);
                String version = String.format(Locale.US, "%s (%d)", pInfo.versionName, Integer.valueOf(pInfo.versionCode));
                Intent mailer = new Intent("android.intent.action.SEND");
                mailer.setType("message/rfc822");
                mailer.putExtra("android.intent.extra.EMAIL", new String[]{"sms@stel.com"});
                mailer.putExtra("android.intent.extra.SUBJECT", "Android registration/login issue " + version + " " + this.emailPhone);
                mailer.putExtra("android.intent.extra.TEXT", "Phone: " + this.requestPhone + "\nApp version: " + version + "\nOS version: SDK " + Build.VERSION.SDK_INT + "\nDevice Name: " + Build.MANUFACTURER + Build.MODEL + "\nLocale: " + Locale.getDefault() + "\nError: " + this.lastError);
                getContext().startActivity(Intent.createChooser(mailer, "Send email..."));
            } catch (Exception e) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("NoMailInstalled", R.string.NoMailInstalled));
            }
        }

        public /* synthetic */ void lambda$new$1$HloginActivity$LoginActivitySmsView(View v) {
            onNextPressed();
        }

        @Override // android.widget.LinearLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            ImageView imageView;
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            if (this.currentType != 3 && (imageView = this.blueImageView) != null) {
                int innerHeight = imageView.getMeasuredHeight() + this.titleTextView.getMeasuredHeight() + this.confirmTextView.getMeasuredHeight() + AndroidUtilities.dp(35.0f);
                int requiredHeight = AndroidUtilities.dp(80.0f);
                int maxHeight = AndroidUtilities.dp(291.0f);
                if (HloginActivity.this.scrollHeight - innerHeight >= requiredHeight) {
                    if (HloginActivity.this.scrollHeight <= maxHeight) {
                        setMeasuredDimension(getMeasuredWidth(), HloginActivity.this.scrollHeight);
                        return;
                    } else {
                        setMeasuredDimension(getMeasuredWidth(), maxHeight);
                        return;
                    }
                }
                setMeasuredDimension(getMeasuredWidth(), innerHeight + requiredHeight);
            }
        }

        @Override // android.widget.LinearLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            int t2;
            super.onLayout(changed, l, t, r, b);
            if (this.currentType != 3 && this.blueImageView != null) {
                int bottom = this.confirmTextView.getBottom();
                int height = getMeasuredHeight() - bottom;
                if (this.problemText.getVisibility() == 0) {
                    int h = this.problemText.getMeasuredHeight();
                    t2 = (bottom + height) - h;
                    TextView textView = this.problemText;
                    textView.layout(textView.getLeft(), t2, this.problemText.getRight(), t2 + h);
                } else if (this.timeText.getVisibility() == 0) {
                    int h2 = this.timeText.getMeasuredHeight();
                    t2 = (bottom + height) - h2;
                    TextView textView2 = this.timeText;
                    textView2.layout(textView2.getLeft(), t2, this.timeText.getRight(), t2 + h2);
                } else {
                    t2 = bottom + height;
                }
                int h3 = this.codeFieldContainer.getMeasuredHeight();
                int t3 = (((t2 - bottom) - h3) / 2) + bottom;
                LinearLayout linearLayout = this.codeFieldContainer;
                linearLayout.layout(linearLayout.getLeft(), t3, this.codeFieldContainer.getRight(), t3 + h3);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onCancelPressed() {
            this.nextPressed = false;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void resendCode() {
            final Bundle params = new Bundle();
            params.putString("phone", this.phone);
            params.putString("ephone", this.emailPhone);
            params.putString("phoneFormated", this.requestPhone);
            this.nextPressed = true;
            TLRPC.TL_auth_resendCode req = new TLRPC.TL_auth_resendCode();
            req.phone_number = this.requestPhone;
            req.phone_code_hash = this.phoneHash;
            ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$2poaMSXaWh71XAkBEyXK9W5TrdE
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$resendCode$3$HloginActivity$LoginActivitySmsView(params, tLObject, tL_error);
                }
            }, 10);
            HloginActivity.this.needShowProgress(0);
        }

        public /* synthetic */ void lambda$resendCode$3$HloginActivity$LoginActivitySmsView(final Bundle params, final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$feOvwhJWL9iOJNALSj5EcEJlASU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$2$HloginActivity$LoginActivitySmsView(error, params, response);
                }
            });
        }

        public /* synthetic */ void lambda$null$2$HloginActivity$LoginActivitySmsView(TLRPC.TL_error error, Bundle params, TLObject response) {
            this.nextPressed = false;
            if (error == null) {
                HloginActivity.this.fillNextCodeParams(params, (TLRPC.TL_auth_sentCode) response);
            } else if (error.text != null) {
                if (error.text.contains("PHONE_NUMBER_INVALID")) {
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("InvalidPhoneNumber", R.string.InvalidPhoneNumber));
                } else if (error.text.contains("PHONE_CODE_EMPTY") || error.text.contains("PHONE_CODE_INVALID")) {
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("InvalidCode", R.string.InvalidCode));
                } else if (error.text.contains("PHONE_CODE_EXPIRED")) {
                    onBackPressed(true);
                    HloginActivity.this.setPage(0, true, null, true);
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("CodeExpired", R.string.CodeExpired));
                } else if (error.text.startsWith("FLOOD_WAIT")) {
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("FloodWait", R.string.FloodWait));
                } else if (error.code != -1000) {
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("ErrorOccurred", R.string.ErrorOccurred) + ShellAdbUtils.COMMAND_LINE_END + error.text);
                }
            }
            HloginActivity.this.needHideProgress(false);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public String getHeaderName() {
            if (this.currentType == 1) {
                return this.phone;
            }
            return LocaleController.getString("YourCode", R.string.YourCode);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean needBackButton() {
            return true;
        }

        /* JADX WARN: Removed duplicated region for block: B:102:0x0376  */
        @Override // im.uwrkaxlmjj.ui.components.SlideView
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void setParams(android.os.Bundle r23, boolean r24) {
            /*
                Method dump skipped, instruction units count: 981
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.hui.login.HloginActivity.LoginActivitySmsView.setParams(android.os.Bundle, boolean):void");
        }

        public /* synthetic */ boolean lambda$setParams$4$HloginActivity$LoginActivitySmsView(int num, View v, int keyCode, KeyEvent event) {
            if (keyCode == 67 && this.codeField[num].length() == 0 && num > 0) {
                EditTextBoldCursor[] editTextBoldCursorArr = this.codeField;
                editTextBoldCursorArr[num - 1].setSelection(editTextBoldCursorArr[num - 1].length());
                this.codeField[num - 1].requestFocus();
                this.codeField[num - 1].dispatchKeyEvent(event);
                return true;
            }
            return false;
        }

        public /* synthetic */ boolean lambda$setParams$5$HloginActivity$LoginActivitySmsView(TextView textView, int i, KeyEvent keyEvent) {
            if (i == 5) {
                onNextPressed();
                return true;
            }
            return false;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void createCodeTimer() {
            if (this.codeTimer != null) {
                return;
            }
            this.codeTime = 15000;
            this.codeTimer = new Timer();
            this.lastCodeTime = System.currentTimeMillis();
            this.codeTimer.schedule(new AnonymousClass4(), 0L, 1000L);
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.login.HloginActivity$LoginActivitySmsView$4, reason: invalid class name */
        class AnonymousClass4 extends TimerTask {
            AnonymousClass4() {
            }

            @Override // java.util.TimerTask, java.lang.Runnable
            public void run() {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$4$k83mZQ8ZNHttGJULBtSuuGMumjU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$run$0$HloginActivity$LoginActivitySmsView$4();
                    }
                });
            }

            public /* synthetic */ void lambda$run$0$HloginActivity$LoginActivitySmsView$4() {
                double currentTime = System.currentTimeMillis();
                double diff = currentTime - LoginActivitySmsView.this.lastCodeTime;
                LoginActivitySmsView.this.lastCodeTime = currentTime;
                LoginActivitySmsView loginActivitySmsView = LoginActivitySmsView.this;
                loginActivitySmsView.codeTime = (int) (((double) loginActivitySmsView.codeTime) - diff);
                if (LoginActivitySmsView.this.codeTime <= 1000) {
                    LoginActivitySmsView.this.problemText.setVisibility(0);
                    LoginActivitySmsView.this.timeText.setVisibility(8);
                    LoginActivitySmsView.this.destroyCodeTimer();
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void destroyCodeTimer() {
            try {
                synchronized (this.timerSync) {
                    if (this.codeTimer != null) {
                        this.codeTimer.cancel();
                        this.codeTimer = null;
                    }
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        private void createTimer() {
            if (this.timeTimer != null) {
                return;
            }
            Timer timer = new Timer();
            this.timeTimer = timer;
            timer.schedule(new AnonymousClass5(), 0L, 1000L);
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.login.HloginActivity$LoginActivitySmsView$5, reason: invalid class name */
        class AnonymousClass5 extends TimerTask {
            AnonymousClass5() {
            }

            @Override // java.util.TimerTask, java.lang.Runnable
            public void run() {
                if (LoginActivitySmsView.this.timeTimer == null) {
                    return;
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$5$S-eVY8MaVLRBG5XcTOM2gqn5WTI
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$run$2$HloginActivity$LoginActivitySmsView$5();
                    }
                });
            }

            public /* synthetic */ void lambda$run$2$HloginActivity$LoginActivitySmsView$5() {
                double currentTime = System.currentTimeMillis();
                double diff = currentTime - LoginActivitySmsView.this.lastCurrentTime;
                LoginActivitySmsView.this.lastCurrentTime = currentTime;
                LoginActivitySmsView loginActivitySmsView = LoginActivitySmsView.this;
                loginActivitySmsView.time = (int) (((double) loginActivitySmsView.time) - diff);
                if (LoginActivitySmsView.this.time >= 1000) {
                    int minutes = (LoginActivitySmsView.this.time / 1000) / 60;
                    int seconds = (LoginActivitySmsView.this.time / 1000) - (minutes * 60);
                    if (LoginActivitySmsView.this.nextType == 4 || LoginActivitySmsView.this.nextType == 3) {
                        LoginActivitySmsView.this.timeText.setText(LocaleController.formatString("CallText", R.string.CallText, Integer.valueOf(minutes), Integer.valueOf(seconds)));
                    } else if (LoginActivitySmsView.this.nextType == 2) {
                        LoginActivitySmsView.this.timeText.setText(LocaleController.formatString("SmsText", R.string.SmsText, Integer.valueOf(minutes), Integer.valueOf(seconds)));
                    }
                    if (LoginActivitySmsView.this.progressView != null) {
                        LoginActivitySmsView.this.progressView.setProgress(1.0f - (LoginActivitySmsView.this.time / LoginActivitySmsView.this.timeout));
                        return;
                    }
                    return;
                }
                if (LoginActivitySmsView.this.progressView != null) {
                    LoginActivitySmsView.this.progressView.setProgress(1.0f);
                }
                LoginActivitySmsView.this.destroyTimer();
                if (LoginActivitySmsView.this.currentType != 3) {
                    if (LoginActivitySmsView.this.currentType == 2 || LoginActivitySmsView.this.currentType == 4) {
                        if (LoginActivitySmsView.this.nextType == 4 || LoginActivitySmsView.this.nextType == 2) {
                            if (LoginActivitySmsView.this.nextType == 4) {
                                LoginActivitySmsView.this.timeText.setText(LocaleController.getString("Calling", R.string.Calling));
                            } else {
                                LoginActivitySmsView.this.timeText.setText(LocaleController.getString("SendingSms", R.string.SendingSms));
                            }
                            LoginActivitySmsView.this.createCodeTimer();
                            TLRPC.TL_auth_resendCode req = new TLRPC.TL_auth_resendCode();
                            req.phone_number = LoginActivitySmsView.this.requestPhone;
                            req.phone_code_hash = LoginActivitySmsView.this.phoneHash;
                            ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$5$G1dqHIAulZTSgZ3RwrtHBAkPY_Y
                                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                    this.f$0.lambda$null$1$HloginActivity$LoginActivitySmsView$5(tLObject, tL_error);
                                }
                            }, 10);
                            return;
                        }
                        if (LoginActivitySmsView.this.nextType == 3) {
                            AndroidUtilities.setWaitingForSms(false);
                            NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveSmsCode);
                            LoginActivitySmsView.this.waitingForEvent = false;
                            LoginActivitySmsView.this.destroyCodeTimer();
                            LoginActivitySmsView.this.resendCode();
                            return;
                        }
                        return;
                    }
                    return;
                }
                AndroidUtilities.setWaitingForCall(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveCall);
                LoginActivitySmsView.this.waitingForEvent = false;
                LoginActivitySmsView.this.destroyCodeTimer();
                LoginActivitySmsView.this.resendCode();
            }

            public /* synthetic */ void lambda$null$1$HloginActivity$LoginActivitySmsView$5(TLObject response, final TLRPC.TL_error error) {
                if (error != null && error.text != null) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$5$waRjGZK-ech9yQZeMtVDQtfA1WQ
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$null$0$HloginActivity$LoginActivitySmsView$5(error);
                        }
                    });
                }
            }

            public /* synthetic */ void lambda$null$0$HloginActivity$LoginActivitySmsView$5(TLRPC.TL_error error) {
                LoginActivitySmsView.this.lastError = error.text;
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void destroyTimer() {
            try {
                synchronized (this.timerSync) {
                    if (this.timeTimer != null) {
                        this.timeTimer.cancel();
                        this.timeTimer = null;
                    }
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public String getCode() {
            if (this.codeField == null) {
                return "";
            }
            StringBuilder codeBuilder = new StringBuilder();
            int a = 0;
            while (true) {
                EditTextBoldCursor[] editTextBoldCursorArr = this.codeField;
                if (a < editTextBoldCursorArr.length) {
                    codeBuilder.append(PhoneFormat.stripExceptNumbers(editTextBoldCursorArr[a].getText().toString()));
                    a++;
                } else {
                    return codeBuilder.toString();
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onNextPressed() {
            if (this.nextPressed || HloginActivity.this.currentViewNum < 1 || HloginActivity.this.currentViewNum > 4) {
                return;
            }
            String code = getCode();
            if (TextUtils.isEmpty(code)) {
                AndroidUtilities.shakeView(this.codeFieldContainer, 2.0f, 0);
                return;
            }
            this.nextPressed = true;
            int i = this.currentType;
            if (i == 2) {
                AndroidUtilities.setWaitingForSms(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveSmsCode);
            } else if (i == 3) {
                AndroidUtilities.setWaitingForCall(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveCall);
            }
            this.waitingForEvent = false;
            final TLRPC.TL_auth_signIn req = new TLRPC.TL_auth_signIn();
            req.phone_number = this.requestPhone;
            req.phone_code = code;
            req.phone_code_hash = this.phoneHash;
            destroyTimer();
            int reqId = ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$RIpRHIjMc_5lH379nxJZPVAXva0
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$onNextPressed$9$HloginActivity$LoginActivitySmsView(req, tLObject, tL_error);
                }
            }, 10);
            HloginActivity.this.needShowProgress(reqId);
        }

        public /* synthetic */ void lambda$onNextPressed$9$HloginActivity$LoginActivitySmsView(final TLRPC.TL_auth_signIn req, final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$d5r3TcouwesPFmzqzeVGthRlcNg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$8$HloginActivity$LoginActivitySmsView(error, response, req);
                }
            });
        }

        public /* synthetic */ void lambda$null$8$HloginActivity$LoginActivitySmsView(TLRPC.TL_error error, TLObject response, final TLRPC.TL_auth_signIn req) {
            int i;
            EditTextBoldCursor[] editTextBoldCursorArr;
            int i2;
            boolean ok = false;
            if (error == null) {
                this.nextPressed = false;
                ok = true;
                HloginActivity.this.needHideProgress(false);
                destroyTimer();
                destroyCodeTimer();
                if (!(response instanceof TLRPC.TL_auth_authorizationSignUpRequired)) {
                    HloginActivity.this.onAuthSuccess((TLRPC.TL_auth_authorization) response);
                } else {
                    TLRPC.TL_auth_authorizationSignUpRequired authorization = (TLRPC.TL_auth_authorizationSignUpRequired) response;
                    if (authorization.terms_of_service != null) {
                        HloginActivity.this.currentTermsOfService = authorization.terms_of_service;
                    }
                    Bundle params = new Bundle();
                    params.putString("phoneFormated", this.requestPhone);
                    params.putString("phoneHash", this.phoneHash);
                    params.putString("code", req.phone_code);
                    HloginActivity.this.setPage(5, true, params, false);
                }
            } else {
                this.lastError = error.text;
                if (error.text.contains("SESSION_PASSWORD_NEEDED")) {
                    ok = true;
                    TLRPC.TL_account_getPassword req2 = new TLRPC.TL_account_getPassword();
                    ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$ZNVJJR5M6E4r3tbAp6qo1ZKbvmo
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$null$7$HloginActivity$LoginActivitySmsView(req, tLObject, tL_error);
                        }
                    }, 10);
                    destroyTimer();
                    destroyCodeTimer();
                } else {
                    HloginActivity.this.needHideProgress(false);
                    if ((this.currentType == 3 && ((i2 = this.nextType) == 4 || i2 == 2)) || ((this.currentType == 2 && ((i = this.nextType) == 4 || i == 3)) || (this.currentType == 4 && this.nextType == 2))) {
                        createTimer();
                    }
                    int i3 = this.currentType;
                    if (i3 == 2) {
                        AndroidUtilities.setWaitingForSms(true);
                        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didReceiveSmsCode);
                    } else if (i3 == 3) {
                        AndroidUtilities.setWaitingForCall(true);
                        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didReceiveCall);
                    }
                    this.waitingForEvent = true;
                    if (this.currentType != 3) {
                        if (error.text.contains("PHONE_NUMBER_INVALID")) {
                            HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("InvalidPhoneNumber", R.string.InvalidPhoneNumber));
                        } else if (error.text.contains("PHONE_CODE_EMPTY") || error.text.contains("PHONE_CODE_INVALID")) {
                            HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("InvalidCode", R.string.InvalidCode));
                            int a = 0;
                            while (true) {
                                editTextBoldCursorArr = this.codeField;
                                if (a >= editTextBoldCursorArr.length) {
                                    break;
                                }
                                editTextBoldCursorArr[a].setText("");
                                a++;
                            }
                            editTextBoldCursorArr[0].requestFocus();
                        } else if (error.text.contains("PHONE_CODE_EXPIRED")) {
                            onBackPressed(true);
                            HloginActivity.this.setPage(0, true, null, true);
                            HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("CodeExpired", R.string.CodeExpired));
                        } else if (error.text.startsWith("FLOOD_WAIT")) {
                            HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("FloodWait", R.string.FloodWait));
                        } else {
                            HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("ErrorOccurred", R.string.ErrorOccurred) + ShellAdbUtils.COMMAND_LINE_END + error.text);
                        }
                    }
                }
            }
            if (ok && this.currentType == 3) {
                AndroidUtilities.endIncomingCall();
            }
        }

        public /* synthetic */ void lambda$null$7$HloginActivity$LoginActivitySmsView(final TLRPC.TL_auth_signIn req, final TLObject response1, final TLRPC.TL_error error1) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$0sZy3kpgR3QtQKLNA2Dbwc5oWdw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$6$HloginActivity$LoginActivitySmsView(error1, response1, req);
                }
            });
        }

        /* JADX WARN: Type inference fix 'apply assigned field type' failed
        java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
        	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
        	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
        	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
        	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
        	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
        	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
        	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
         */
        public /* synthetic */ void lambda$null$6$HloginActivity$LoginActivitySmsView(TLRPC.TL_error tL_error, TLObject tLObject, TLRPC.TL_auth_signIn tL_auth_signIn) {
            this.nextPressed = false;
            HloginActivity.this.needHideProgress(false);
            if (tL_error != null) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), tL_error.text);
                return;
            }
            TLRPC.TL_account_password tL_account_password = (TLRPC.TL_account_password) tLObject;
            if (!TwoStepVerificationActivity.canHandleCurrentPassword(tL_account_password, true)) {
                AlertsCreator.showUpdateAppAlert(HloginActivity.this.getParentActivity(), LocaleController.getString("UpdateAppAlert", R.string.UpdateAppAlert), true);
                return;
            }
            Bundle bundle = new Bundle();
            if (tL_account_password.current_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
                TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow tL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) tL_account_password.current_algo;
                bundle.putString("current_salt1", Utilities.bytesToHex(tL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow.salt1));
                bundle.putString("current_salt2", Utilities.bytesToHex(tL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow.salt2));
                bundle.putString("current_p", Utilities.bytesToHex(tL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow.p));
                bundle.putInt("current_g", tL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow.g);
                bundle.putString("current_srp_B", Utilities.bytesToHex(tL_account_password.srp_B));
                bundle.putLong("current_srp_id", tL_account_password.srp_id);
                bundle.putInt("passwordType", 1);
            }
            bundle.putString(TrackReferenceTypeBox.TYPE1, tL_account_password.hint != null ? tL_account_password.hint : "");
            bundle.putString("email_unconfirmed_pattern", tL_account_password.email_unconfirmed_pattern != null ? tL_account_password.email_unconfirmed_pattern : "");
            bundle.putString("phoneFormated", this.requestPhone);
            bundle.putString("phoneHash", this.phoneHash);
            bundle.putString("code", tL_auth_signIn.phone_code);
            bundle.putInt("has_recovery", tL_account_password.has_recovery ? 1 : 0);
            HloginActivity.this.setPage(6, true, bundle, false);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean onBackPressed(boolean force) {
            if (!force) {
                XDialog.Builder builder = new XDialog.Builder(HloginActivity.this.getParentActivity());
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setMessage(LocaleController.getString("StopVerification", R.string.StopVerification));
                builder.setPositiveButton(LocaleController.getString("Continue", R.string.Continue), null);
                builder.setNegativeButton(LocaleController.getString("Stop", R.string.Stop), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$bbUewSn_BGrjwkwLBnfOY4QjVIs
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onBackPressed$10$HloginActivity$LoginActivitySmsView(dialogInterface, i);
                    }
                });
                HloginActivity.this.showDialog(builder.create());
                return false;
            }
            this.nextPressed = false;
            HloginActivity.this.needHideProgress(true);
            TLRPC.TL_auth_cancelCode req = new TLRPC.TL_auth_cancelCode();
            req.phone_number = this.requestPhone;
            req.phone_code_hash = this.phoneHash;
            ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$fE1odCTGG5xboZYRQKh84deUWHw
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    HloginActivity.LoginActivitySmsView.lambda$onBackPressed$11(tLObject, tL_error);
                }
            }, 10);
            destroyTimer();
            destroyCodeTimer();
            this.currentParams = null;
            int i = this.currentType;
            if (i == 2) {
                AndroidUtilities.setWaitingForSms(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveSmsCode);
            } else if (i == 3) {
                AndroidUtilities.setWaitingForCall(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveCall);
            }
            this.waitingForEvent = false;
            return true;
        }

        public /* synthetic */ void lambda$onBackPressed$10$HloginActivity$LoginActivitySmsView(DialogInterface dialogInterface, int i) {
            onBackPressed(true);
            HloginActivity.this.setPage(0, true, null, true);
        }

        static /* synthetic */ void lambda$onBackPressed$11(TLObject response, TLRPC.TL_error error) {
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onDestroyActivity() {
            super.onDestroyActivity();
            int i = this.currentType;
            if (i == 2) {
                AndroidUtilities.setWaitingForSms(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveSmsCode);
            } else if (i == 3) {
                AndroidUtilities.setWaitingForCall(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveCall);
            }
            this.waitingForEvent = false;
            destroyTimer();
            destroyCodeTimer();
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onShow() {
            super.onShow();
            if (this.currentType == 3) {
                return;
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivitySmsView$18Te9qMWEeSlsEyb-Kry6F_mrXg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onShow$12$HloginActivity$LoginActivitySmsView();
                }
            }, 100L);
        }

        public /* synthetic */ void lambda$onShow$12$HloginActivity$LoginActivitySmsView() {
            EditTextBoldCursor[] editTextBoldCursorArr = this.codeField;
            if (editTextBoldCursorArr != null) {
                for (int a = editTextBoldCursorArr.length - 1; a >= 0; a--) {
                    if (a == 0 || this.codeField[a].length() != 0) {
                        this.codeField[a].requestFocus();
                        EditTextBoldCursor[] editTextBoldCursorArr2 = this.codeField;
                        editTextBoldCursorArr2[a].setSelection(editTextBoldCursorArr2[a].length());
                        AndroidUtilities.showKeyboard(this.codeField[a]);
                        return;
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
        public void didReceivedNotification(int id, int account, Object... args) {
            if (!this.waitingForEvent || this.codeField == null) {
                return;
            }
            if (id == NotificationCenter.didReceiveSmsCode) {
                this.codeField[0].setText("" + args[0]);
                onNextPressed();
                return;
            }
            if (id == NotificationCenter.didReceiveCall) {
                String num = "" + args[0];
                if (!AndroidUtilities.checkPhonePattern(this.pattern, num)) {
                    return;
                }
                if (!this.pattern.equals("*")) {
                    this.catchedPhone = num;
                    AndroidUtilities.endIncomingCall();
                }
                this.ignoreOnTextChange = true;
                this.codeField[0].setText(num);
                this.ignoreOnTextChange = false;
                onNextPressed();
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void saveStateParams(Bundle bundle) {
            String code = getCode();
            if (code.length() != 0) {
                bundle.putString("smsview_code_" + this.currentType, code);
            }
            String str = this.catchedPhone;
            if (str != null) {
                bundle.putString("catchedPhone", str);
            }
            if (this.currentParams != null) {
                bundle.putBundle("smsview_params_" + this.currentType, this.currentParams);
            }
            int i = this.time;
            if (i != 0) {
                bundle.putInt("time", i);
            }
            int i2 = this.openTime;
            if (i2 != 0) {
                bundle.putInt("open", i2);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void restoreStateParams(Bundle bundle) {
            EditTextBoldCursor[] editTextBoldCursorArr;
            Bundle bundle2 = bundle.getBundle("smsview_params_" + this.currentType);
            this.currentParams = bundle2;
            if (bundle2 != null) {
                setParams(bundle2, true);
            }
            String catched = bundle.getString("catchedPhone");
            if (catched != null) {
                this.catchedPhone = catched;
            }
            String code = bundle.getString("smsview_code_" + this.currentType);
            if (code != null && (editTextBoldCursorArr = this.codeField) != null) {
                editTextBoldCursorArr[0].setText(code);
            }
            int t = bundle.getInt("time");
            if (t != 0) {
                this.time = t;
            }
            int t2 = bundle.getInt("open");
            if (t2 != 0) {
                this.openTime = t2;
            }
        }
    }

    public class LoginActivityPasswordView extends SlideView {
        private TextView cancelButton;
        private EditTextBoldCursor codeField;
        private TextView confirmTextView;
        private Bundle currentParams;
        private int current_g;
        private byte[] current_p;
        private byte[] current_salt1;
        private byte[] current_salt2;
        private byte[] current_srp_B;
        private long current_srp_id;
        private String email_unconfirmed_pattern;
        private boolean has_recovery;
        private String hint;
        private boolean nextPressed;
        private int passwordType;
        private String phoneCode;
        private String phoneHash;
        private String requestPhone;
        private TextView resetAccountButton;
        private TextView resetAccountText;

        public LoginActivityPasswordView(Context context) {
            super(context);
            setOrientation(1);
            TextView textView = new TextView(context);
            this.confirmTextView = textView;
            textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.confirmTextView.setTextSize(1, 14.0f);
            this.confirmTextView.setGravity(LocaleController.isRTL ? 5 : 3);
            this.confirmTextView.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            this.confirmTextView.setText(LocaleController.getString("LoginPasswordText", R.string.LoginPasswordText));
            addView(this.confirmTextView, LayoutHelper.createLinear(-2, -2, LocaleController.isRTL ? 5 : 3));
            EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(context);
            this.codeField = editTextBoldCursor;
            editTextBoldCursor.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.codeField.setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.codeField.setCursorSize(AndroidUtilities.dp(20.0f));
            this.codeField.setCursorWidth(1.5f);
            this.codeField.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
            this.codeField.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
            this.codeField.setHint(LocaleController.getString("LoginPassword", R.string.LoginPassword));
            this.codeField.setImeOptions(268435461);
            this.codeField.setTextSize(1, 18.0f);
            this.codeField.setMaxLines(1);
            this.codeField.setPadding(0, 0, 0, 0);
            this.codeField.setInputType(TsExtractor.TS_STREAM_TYPE_AC3);
            this.codeField.setTransformationMethod(PasswordTransformationMethod.getInstance());
            this.codeField.setTypeface(Typeface.DEFAULT);
            this.codeField.setGravity(LocaleController.isRTL ? 5 : 3);
            addView(this.codeField, LayoutHelper.createLinear(-1, 36, 1, 0, 20, 0, 0));
            this.codeField.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$3zeQ209agrsxEvKKH1_6woVSODA
                @Override // android.widget.TextView.OnEditorActionListener
                public final boolean onEditorAction(TextView textView2, int i, KeyEvent keyEvent) {
                    return this.f$0.lambda$new$0$HloginActivity$LoginActivityPasswordView(textView2, i, keyEvent);
                }
            });
            TextView textView2 = new TextView(context);
            this.cancelButton = textView2;
            textView2.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            this.cancelButton.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText4));
            this.cancelButton.setText(LocaleController.getString("ForgotPassword", R.string.ForgotPassword));
            this.cancelButton.setTextSize(1, 14.0f);
            this.cancelButton.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            this.cancelButton.setPadding(0, AndroidUtilities.dp(14.0f), 0, 0);
            addView(this.cancelButton, LayoutHelper.createLinear(-1, -2, (LocaleController.isRTL ? 5 : 3) | 48));
            this.cancelButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$uNiED0rlbdTHqGnNk8V1etxd2P0
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$4$HloginActivity$LoginActivityPasswordView(view);
                }
            });
            TextView textView3 = new TextView(context);
            this.resetAccountButton = textView3;
            textView3.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            this.resetAccountButton.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText6));
            this.resetAccountButton.setVisibility(8);
            this.resetAccountButton.setText(LocaleController.getString("ResetMyAccount", R.string.ResetMyAccount));
            this.resetAccountButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.resetAccountButton.setTextSize(1, 14.0f);
            this.resetAccountButton.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            this.resetAccountButton.setPadding(0, AndroidUtilities.dp(14.0f), 0, 0);
            addView(this.resetAccountButton, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 0, 34, 0, 0));
            this.resetAccountButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$zXs2Bqn2cPianTuy6aDivu4PT8Q
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$8$HloginActivity$LoginActivityPasswordView(view);
                }
            });
            TextView textView4 = new TextView(context);
            this.resetAccountText = textView4;
            textView4.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            this.resetAccountText.setVisibility(8);
            this.resetAccountText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.resetAccountText.setText(LocaleController.getString("ResetMyAccountText", R.string.ResetMyAccountText));
            this.resetAccountText.setTextSize(1, 14.0f);
            this.resetAccountText.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            addView(this.resetAccountText, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 0, 7, 0, 14));
        }

        public /* synthetic */ boolean lambda$new$0$HloginActivity$LoginActivityPasswordView(TextView textView, int i, KeyEvent keyEvent) {
            if (i == 5) {
                onNextPressed();
                return true;
            }
            return false;
        }

        public /* synthetic */ void lambda$new$4$HloginActivity$LoginActivityPasswordView(View view) {
            if (HloginActivity.this.doneProgressView.getTag() != null) {
                return;
            }
            if (this.has_recovery) {
                HloginActivity.this.needShowProgress(0);
                TLRPC.TL_auth_requestPasswordRecovery req = new TLRPC.TL_auth_requestPasswordRecovery();
                ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$UJ3Qm7oRr70YLBn5MN1jHtfRrcE
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$null$3$HloginActivity$LoginActivityPasswordView(tLObject, tL_error);
                    }
                }, 10);
            } else {
                this.resetAccountText.setVisibility(0);
                this.resetAccountButton.setVisibility(0);
                AndroidUtilities.hideKeyboard(this.codeField);
                HloginActivity.this.needShowAlert(LocaleController.getString("RestorePasswordNoEitle", R.string.RestorePasswordNoEmailTitle), LocaleController.getString("RestorePasswordNoEmailText", R.string.RestorePasswordNoEmailText));
            }
        }

        public /* synthetic */ void lambda$null$3$HloginActivity$LoginActivityPasswordView(final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$txqVT3Z-YHSZN-Nn9ZxVkqqPjf4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$2$HloginActivity$LoginActivityPasswordView(error, response);
                }
            });
        }

        public /* synthetic */ void lambda$null$2$HloginActivity$LoginActivityPasswordView(TLRPC.TL_error error, TLObject response) {
            String timeString;
            HloginActivity.this.needHideProgress(false);
            if (error == null) {
                final TLRPC.TL_auth_passwordRecovery res = (TLRPC.TL_auth_passwordRecovery) response;
                AlertDialog.Builder builder = new AlertDialog.Builder(HloginActivity.this.getParentActivity());
                builder.setMessage(LocaleController.formatString("RestoreEmailSent", R.string.RestoreEmailSent, res.email_pattern));
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$OiyZXnN9i6f7FxGGpZV6Zhyum_k
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$1$HloginActivity$LoginActivityPasswordView(res, dialogInterface, i);
                    }
                });
                Dialog dialog = HloginActivity.this.showDialog(builder.create());
                if (dialog != null) {
                    dialog.setCanceledOnTouchOutside(false);
                    dialog.setCancelable(false);
                    return;
                }
                return;
            }
            if (!error.text.startsWith("FLOOD_WAIT")) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), error.text);
                return;
            }
            int time = Utilities.parseInt(error.text).intValue();
            if (time < 60) {
                timeString = LocaleController.formatPluralString("Seconds", time);
            } else {
                timeString = LocaleController.formatPluralString("Minutes", time / 60);
            }
            HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString));
        }

        public /* synthetic */ void lambda$null$1$HloginActivity$LoginActivityPasswordView(TLRPC.TL_auth_passwordRecovery res, DialogInterface dialogInterface, int i) {
            Bundle bundle = new Bundle();
            bundle.putString("email_unconfirmed_pattern", res.email_pattern);
            HloginActivity.this.setPage(7, true, bundle, false);
        }

        public /* synthetic */ void lambda$new$8$HloginActivity$LoginActivityPasswordView(View view) {
            if (HloginActivity.this.doneProgressView.getTag() != null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(HloginActivity.this.getParentActivity());
            builder.setMessage(LocaleController.getString("ResetMyAccountWarningText", R.string.ResetMyAccountWarningText));
            builder.setTitle(LocaleController.getString("ResetMyAccountWarning", R.string.ResetMyAccountWarning));
            builder.setPositiveButton(LocaleController.getString("ResetMyAccountWarningReset", R.string.ResetMyAccountWarningReset), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$CMZLBXwa84Dpt2Gi_g_KiuT2fLA
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$7$HloginActivity$LoginActivityPasswordView(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            HloginActivity.this.showDialog(builder.create());
        }

        public /* synthetic */ void lambda$null$7$HloginActivity$LoginActivityPasswordView(DialogInterface dialogInterface, int i) {
            HloginActivity.this.needShowProgress(0);
            TLRPC.TL_account_deleteAccount req = new TLRPC.TL_account_deleteAccount();
            req.reason = "Forgot password";
            ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$-ExRAJkrV6NzXjJUMrfW-artroc
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$6$HloginActivity$LoginActivityPasswordView(tLObject, tL_error);
                }
            }, 10);
        }

        public /* synthetic */ void lambda$null$6$HloginActivity$LoginActivityPasswordView(TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$FvuKs6x0lV9HnRfhrlpc_uSdXD0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$5$HloginActivity$LoginActivityPasswordView(error);
                }
            });
        }

        public /* synthetic */ void lambda$null$5$HloginActivity$LoginActivityPasswordView(TLRPC.TL_error error) {
            HloginActivity.this.needHideProgress(false);
            if (error == null) {
                Bundle params = new Bundle();
                params.putString("phoneFormated", this.requestPhone);
                params.putString("phoneHash", this.phoneHash);
                params.putString("code", this.phoneCode);
                HloginActivity.this.setPage(5, true, params, false);
                return;
            }
            if (error.text.equals("2FA_RECENT_CONFIRM")) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("ResetAccountCancelledAlert", R.string.ResetAccountCancelledAlert));
                return;
            }
            if (!error.text.startsWith("2FA_CONFIRM_WAIT_")) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), error.text);
                return;
            }
            Bundle params2 = new Bundle();
            params2.putString("phoneFormated", this.requestPhone);
            params2.putString("phoneHash", this.phoneHash);
            params2.putString("code", this.phoneCode);
            params2.putInt("startTime", ConnectionsManager.getInstance(HloginActivity.this.currentAccount).getCurrentTime());
            params2.putInt("waitTime", Utilities.parseInt(error.text.replace("2FA_CONFIRM_WAIT_", "")).intValue());
            HloginActivity.this.setPage(8, true, params2, false);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public String getHeaderName() {
            return LocaleController.getString("LoginPassword", R.string.LoginPassword);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onCancelPressed() {
            this.nextPressed = false;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void setParams(Bundle params, boolean restore) {
            if (params == null) {
                return;
            }
            if (params.isEmpty()) {
                this.resetAccountButton.setVisibility(0);
                this.resetAccountText.setVisibility(0);
                AndroidUtilities.hideKeyboard(this.codeField);
                return;
            }
            this.resetAccountButton.setVisibility(8);
            this.resetAccountText.setVisibility(8);
            this.codeField.setText("");
            this.currentParams = params;
            this.current_salt1 = Utilities.hexToBytes(params.getString("current_salt1"));
            this.current_salt2 = Utilities.hexToBytes(this.currentParams.getString("current_salt2"));
            this.current_p = Utilities.hexToBytes(this.currentParams.getString("current_p"));
            this.current_g = this.currentParams.getInt("current_g");
            this.current_srp_B = Utilities.hexToBytes(this.currentParams.getString("current_srp_B"));
            this.current_srp_id = this.currentParams.getLong("current_srp_id");
            this.passwordType = this.currentParams.getInt("passwordType");
            this.hint = this.currentParams.getString(TrackReferenceTypeBox.TYPE1);
            this.has_recovery = this.currentParams.getInt("has_recovery") == 1;
            this.email_unconfirmed_pattern = this.currentParams.getString("email_unconfirmed_pattern");
            this.requestPhone = params.getString("phoneFormated");
            this.phoneHash = params.getString("phoneHash");
            this.phoneCode = params.getString("code");
            String str = this.hint;
            if (str != null && str.length() > 0) {
                this.codeField.setHint(this.hint);
            } else {
                this.codeField.setHint(LocaleController.getString("LoginPassword", R.string.LoginPassword));
            }
        }

        private void onPasscodeError(boolean clear) {
            if (HloginActivity.this.getParentActivity() == null) {
                return;
            }
            Vibrator v = (Vibrator) HloginActivity.this.getParentActivity().getSystemService("vibrator");
            if (v != null) {
                v.vibrate(200L);
            }
            if (clear) {
                this.codeField.setText("");
            }
            AndroidUtilities.shakeView(this.confirmTextView, 2.0f, 0);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onNextPressed() {
            if (this.nextPressed) {
                return;
            }
            final String oldPassword = this.codeField.getText().toString();
            if (oldPassword.length() == 0) {
                onPasscodeError(false);
                return;
            }
            this.nextPressed = true;
            HloginActivity.this.needShowProgress(0);
            Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$eA7f2LPm-fHhV4wCfR2cGQs0hh8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onNextPressed$13$HloginActivity$LoginActivityPasswordView(oldPassword);
                }
            });
        }

        public /* synthetic */ void lambda$onNextPressed$13$HloginActivity$LoginActivityPasswordView(String oldPassword) {
            byte[] passwordBytes;
            TLRPC.PasswordKdfAlgo current_algo = null;
            if (this.passwordType == 1) {
                TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo = new TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow();
                algo.salt1 = this.current_salt1;
                algo.salt2 = this.current_salt2;
                algo.g = this.current_g;
                algo.p = this.current_p;
                current_algo = algo;
            }
            if (current_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
                byte[] passwordBytes2 = AndroidUtilities.getStringBytes(oldPassword);
                passwordBytes = SRPHelper.getX(passwordBytes2, (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) current_algo);
            } else {
                passwordBytes = null;
            }
            TLRPC.TL_auth_checkPassword req = new TLRPC.TL_auth_checkPassword();
            RequestDelegate requestDelegate = new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$3MNmoY4eBf37g4vWnVLm6QmceaI
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$12$HloginActivity$LoginActivityPasswordView(tLObject, tL_error);
                }
            };
            if (current_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
                TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo2 = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) current_algo;
                algo2.salt1 = this.current_salt1;
                algo2.salt2 = this.current_salt2;
                algo2.g = this.current_g;
                algo2.p = this.current_p;
                req.password = SRPHelper.startCheck(passwordBytes, this.current_srp_id, this.current_srp_B, algo2);
                if (req.password != null) {
                    ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req, requestDelegate, 10);
                    return;
                }
                TLRPC.TL_error error = new TLRPC.TL_error();
                error.text = "PASSWORD_HASH_INVALID";
                requestDelegate.run(null, error);
            }
        }

        public /* synthetic */ void lambda$null$12$HloginActivity$LoginActivityPasswordView(final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$q08pUQxcHiDJrPmCwmrXTxKCNOw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$11$HloginActivity$LoginActivityPasswordView(error, response);
                }
            });
        }

        public /* synthetic */ void lambda$null$11$HloginActivity$LoginActivityPasswordView(TLRPC.TL_error error, TLObject response) {
            String timeString;
            this.nextPressed = false;
            if (error == null || !"SRP_ID_INVALID".equals(error.text)) {
                HloginActivity.this.needHideProgress(false);
                if (response instanceof TLRPC.TL_auth_authorization) {
                    HloginActivity.this.onAuthSuccess((TLRPC.TL_auth_authorization) response);
                    return;
                }
                if (error.text.equals("PASSWORD_HASH_INVALID")) {
                    onPasscodeError(true);
                    return;
                }
                if (!error.text.startsWith("FLOOD_WAIT")) {
                    HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), error.text);
                    return;
                }
                int time = Utilities.parseInt(error.text).intValue();
                if (time < 60) {
                    timeString = LocaleController.formatPluralString("Seconds", time);
                } else {
                    timeString = LocaleController.formatPluralString("Minutes", time / 60);
                }
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString));
                return;
            }
            TLRPC.TL_account_getPassword getPasswordReq = new TLRPC.TL_account_getPassword();
            ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(getPasswordReq, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$pIUUhTlZ7tL6hDaHVzL5pCQlOXw
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$10$HloginActivity$LoginActivityPasswordView(tLObject, tL_error);
                }
            }, 8);
        }

        public /* synthetic */ void lambda$null$10$HloginActivity$LoginActivityPasswordView(final TLObject response2, final TLRPC.TL_error error2) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$Zv9cTewwR6ZqZD_5ns6149_pxzY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$9$HloginActivity$LoginActivityPasswordView(error2, response2);
                }
            });
        }

        public /* synthetic */ void lambda$null$9$HloginActivity$LoginActivityPasswordView(TLRPC.TL_error error2, TLObject response2) {
            if (error2 == null) {
                TLRPC.TL_account_password password = (TLRPC.TL_account_password) response2;
                this.current_srp_B = password.srp_B;
                this.current_srp_id = password.srp_id;
                onNextPressed();
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean needBackButton() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean onBackPressed(boolean force) {
            this.nextPressed = false;
            HloginActivity.this.needHideProgress(true);
            this.currentParams = null;
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onShow() {
            super.onShow();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityPasswordView$TBugWa_8RhfybeFSiJwB7xI2m-Y
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onShow$14$HloginActivity$LoginActivityPasswordView();
                }
            }, 100L);
        }

        public /* synthetic */ void lambda$onShow$14$HloginActivity$LoginActivityPasswordView() {
            EditTextBoldCursor editTextBoldCursor = this.codeField;
            if (editTextBoldCursor != null) {
                editTextBoldCursor.requestFocus();
                EditTextBoldCursor editTextBoldCursor2 = this.codeField;
                editTextBoldCursor2.setSelection(editTextBoldCursor2.length());
                AndroidUtilities.showKeyboard(this.codeField);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void saveStateParams(Bundle bundle) {
            String code = this.codeField.getText().toString();
            if (code.length() != 0) {
                bundle.putString("passview_code", code);
            }
            Bundle bundle2 = this.currentParams;
            if (bundle2 != null) {
                bundle.putBundle("passview_params", bundle2);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void restoreStateParams(Bundle bundle) {
            Bundle bundle2 = bundle.getBundle("passview_params");
            this.currentParams = bundle2;
            if (bundle2 != null) {
                setParams(bundle2, true);
            }
            String code = bundle.getString("passview_code");
            if (code != null) {
                this.codeField.setText(code);
            }
        }
    }

    public class LoginActivityResetWaitView extends SlideView {
        private TextView confirmTextView;
        private Bundle currentParams;
        private String phoneCode;
        private String phoneHash;
        private String requestPhone;
        private TextView resetAccountButton;
        private TextView resetAccountText;
        private TextView resetAccountTime;
        private int startTime;
        private Runnable timeRunnable;
        private int waitTime;

        public LoginActivityResetWaitView(Context context) {
            super(context);
            setOrientation(1);
            TextView textView = new TextView(context);
            this.confirmTextView = textView;
            textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.confirmTextView.setTextSize(1, 14.0f);
            this.confirmTextView.setGravity(LocaleController.isRTL ? 5 : 3);
            this.confirmTextView.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            addView(this.confirmTextView, LayoutHelper.createLinear(-2, -2, LocaleController.isRTL ? 5 : 3));
            TextView textView2 = new TextView(context);
            this.resetAccountText = textView2;
            textView2.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            this.resetAccountText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.resetAccountText.setText(LocaleController.getString("ResetAccountStatus", R.string.ResetAccountStatus));
            this.resetAccountText.setTextSize(1, 14.0f);
            this.resetAccountText.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            addView(this.resetAccountText, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 0, 24, 0, 0));
            TextView textView3 = new TextView(context);
            this.resetAccountTime = textView3;
            textView3.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            this.resetAccountTime.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.resetAccountTime.setTextSize(1, 14.0f);
            this.resetAccountTime.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            addView(this.resetAccountTime, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 0, 2, 0, 0));
            TextView textView4 = new TextView(context);
            this.resetAccountButton = textView4;
            textView4.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
            this.resetAccountButton.setText(LocaleController.getString("ResetAccountButton", R.string.ResetAccountButton));
            this.resetAccountButton.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.resetAccountButton.setTextSize(1, 14.0f);
            this.resetAccountButton.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            this.resetAccountButton.setPadding(0, AndroidUtilities.dp(14.0f), 0, 0);
            addView(this.resetAccountButton, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 0, 7, 0, 0));
            this.resetAccountButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityResetWaitView$bKmV0enyX7Pz3KSnfyfk-IckDuE
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$3$HloginActivity$LoginActivityResetWaitView(view);
                }
            });
        }

        public /* synthetic */ void lambda$new$3$HloginActivity$LoginActivityResetWaitView(View view) {
            if (HloginActivity.this.doneProgressView.getTag() != null || Math.abs(ConnectionsManager.getInstance(HloginActivity.this.currentAccount).getCurrentTime() - this.startTime) < this.waitTime) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(HloginActivity.this.getParentActivity());
            builder.setMessage(LocaleController.getString("ResetMyAccountWarningText", R.string.ResetMyAccountWarningText));
            builder.setTitle(LocaleController.getString("ResetMyAccountWarning", R.string.ResetMyAccountWarning));
            builder.setPositiveButton(LocaleController.getString("ResetMyAccountWarningReset", R.string.ResetMyAccountWarningReset), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityResetWaitView$3Pfj3VgAeMGTwTuH5bLIynduyjM
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$2$HloginActivity$LoginActivityResetWaitView(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            HloginActivity.this.showDialog(builder.create());
        }

        public /* synthetic */ void lambda$null$2$HloginActivity$LoginActivityResetWaitView(DialogInterface dialogInterface, int i) {
            HloginActivity.this.needShowProgress(0);
            TLRPC.TL_account_deleteAccount req = new TLRPC.TL_account_deleteAccount();
            req.reason = "Forgot password";
            ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityResetWaitView$Wtwh6A5xnKZE3ix5XIkJs1D2-74
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$1$HloginActivity$LoginActivityResetWaitView(tLObject, tL_error);
                }
            }, 10);
        }

        public /* synthetic */ void lambda$null$1$HloginActivity$LoginActivityResetWaitView(TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityResetWaitView$LHlGgXhMKvvRKrJU6wxlNa7O55w
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$HloginActivity$LoginActivityResetWaitView(error);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$HloginActivity$LoginActivityResetWaitView(TLRPC.TL_error error) {
            HloginActivity.this.needHideProgress(false);
            if (error == null) {
                Bundle params = new Bundle();
                params.putString("phoneFormated", this.requestPhone);
                params.putString("phoneHash", this.phoneHash);
                params.putString("code", this.phoneCode);
                HloginActivity.this.setPage(5, true, params, false);
                return;
            }
            if (error.text.equals("2FA_RECENT_CONFIRM")) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("ResetAccountCancelledAlert", R.string.ResetAccountCancelledAlert));
            } else {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), error.text);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public String getHeaderName() {
            return LocaleController.getString("ResetAccount", R.string.ResetAccount);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void updateTimeText() {
            int timeLeft = Math.max(0, this.waitTime - (ConnectionsManager.getInstance(HloginActivity.this.currentAccount).getCurrentTime() - this.startTime));
            int days = timeLeft / 86400;
            int hours = (timeLeft - (days * 86400)) / 3600;
            int minutes = ((timeLeft - (86400 * days)) - (hours * 3600)) / 60;
            int seconds = timeLeft % 60;
            if (days != 0) {
                this.resetAccountTime.setText(AndroidUtilities.replaceTags(LocaleController.formatPluralString("DaysBold", days) + " " + LocaleController.formatPluralString("HoursBold", hours) + " " + LocaleController.formatPluralString("MinutesBold", minutes)));
            } else {
                this.resetAccountTime.setText(AndroidUtilities.replaceTags(LocaleController.formatPluralString("HoursBold", hours) + " " + LocaleController.formatPluralString("MinutesBold", minutes) + " " + LocaleController.formatPluralString("SecondsBold", seconds)));
            }
            if (timeLeft > 0) {
                this.resetAccountButton.setTag(Theme.key_windowBackgroundWhiteGrayText6);
                this.resetAccountButton.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            } else {
                this.resetAccountButton.setTag(Theme.key_windowBackgroundWhiteRedText6);
                this.resetAccountButton.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText6));
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void setParams(Bundle params, boolean restore) {
            if (params == null) {
                return;
            }
            this.currentParams = params;
            this.requestPhone = params.getString("phoneFormated");
            this.phoneHash = params.getString("phoneHash");
            this.phoneCode = params.getString("code");
            this.startTime = params.getInt("startTime");
            this.waitTime = params.getInt("waitTime");
            this.confirmTextView.setText(AndroidUtilities.replaceTags(LocaleController.formatString("ResetAccountInfo", R.string.ResetAccountInfo, LocaleController.addNbsp(PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + this.requestPhone)))));
            updateTimeText();
            Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.HloginActivity.LoginActivityResetWaitView.1
                @Override // java.lang.Runnable
                public void run() {
                    if (LoginActivityResetWaitView.this.timeRunnable == this) {
                        LoginActivityResetWaitView.this.updateTimeText();
                        AndroidUtilities.runOnUIThread(LoginActivityResetWaitView.this.timeRunnable, 1000L);
                    }
                }
            };
            this.timeRunnable = runnable;
            AndroidUtilities.runOnUIThread(runnable, 1000L);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean needBackButton() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean onBackPressed(boolean force) {
            HloginActivity.this.needHideProgress(true);
            AndroidUtilities.cancelRunOnUIThread(this.timeRunnable);
            this.timeRunnable = null;
            this.currentParams = null;
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void saveStateParams(Bundle bundle) {
            Bundle bundle2 = this.currentParams;
            if (bundle2 != null) {
                bundle.putBundle("resetview_params", bundle2);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void restoreStateParams(Bundle bundle) {
            Bundle bundle2 = bundle.getBundle("resetview_params");
            this.currentParams = bundle2;
            if (bundle2 != null) {
                setParams(bundle2, true);
            }
        }
    }

    public class LoginActivityRecoverView extends SlideView {
        private TextView cancelButton;
        private EditTextBoldCursor codeField;
        private TextView confirmTextView;
        private Bundle currentParams;
        private String email_unconfirmed_pattern;
        private boolean nextPressed;

        public LoginActivityRecoverView(Context context) {
            super(context);
            setOrientation(1);
            TextView textView = new TextView(context);
            this.confirmTextView = textView;
            textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.confirmTextView.setTextSize(1, 14.0f);
            this.confirmTextView.setGravity(LocaleController.isRTL ? 5 : 3);
            this.confirmTextView.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            this.confirmTextView.setText(LocaleController.getString("RestoreEmailSentInfo", R.string.RestoreEmailSentInfo));
            addView(this.confirmTextView, LayoutHelper.createLinear(-2, -2, LocaleController.isRTL ? 5 : 3));
            EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(context);
            this.codeField = editTextBoldCursor;
            editTextBoldCursor.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.codeField.setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.codeField.setCursorSize(AndroidUtilities.dp(20.0f));
            this.codeField.setCursorWidth(1.5f);
            this.codeField.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
            this.codeField.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
            this.codeField.setHint(LocaleController.getString("PasswordCode", R.string.PasswordCode));
            this.codeField.setImeOptions(268435461);
            this.codeField.setTextSize(1, 18.0f);
            this.codeField.setMaxLines(1);
            this.codeField.setPadding(0, 0, 0, 0);
            this.codeField.setInputType(3);
            this.codeField.setTransformationMethod(PasswordTransformationMethod.getInstance());
            this.codeField.setTypeface(Typeface.DEFAULT);
            this.codeField.setGravity(LocaleController.isRTL ? 5 : 3);
            addView(this.codeField, LayoutHelper.createLinear(-1, 36, 1, 0, 20, 0, 0));
            this.codeField.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRecoverView$Uj3e88idYV08YvOtGJIH0bPL9oE
                @Override // android.widget.TextView.OnEditorActionListener
                public final boolean onEditorAction(TextView textView2, int i, KeyEvent keyEvent) {
                    return this.f$0.lambda$new$0$HloginActivity$LoginActivityRecoverView(textView2, i, keyEvent);
                }
            });
            TextView textView2 = new TextView(context);
            this.cancelButton = textView2;
            textView2.setGravity((LocaleController.isRTL ? 5 : 3) | 80);
            this.cancelButton.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText4));
            this.cancelButton.setTextSize(1, 14.0f);
            this.cancelButton.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            this.cancelButton.setPadding(0, AndroidUtilities.dp(14.0f), 0, 0);
            addView(this.cancelButton, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 80, 0, 0, 0, 14));
            this.cancelButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRecoverView$DAaPM5IGvTF5SKS4STa8gfFUv1Y
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$2$HloginActivity$LoginActivityRecoverView(view);
                }
            });
        }

        public /* synthetic */ boolean lambda$new$0$HloginActivity$LoginActivityRecoverView(TextView textView, int i, KeyEvent keyEvent) {
            if (i == 5) {
                onNextPressed();
                return true;
            }
            return false;
        }

        public /* synthetic */ void lambda$new$2$HloginActivity$LoginActivityRecoverView(View view) {
            AlertDialog.Builder builder = new AlertDialog.Builder(HloginActivity.this.getParentActivity());
            builder.setMessage(LocaleController.getString("RestoreEmailTroubleText", R.string.RestoreEmailTroubleText));
            builder.setTitle(LocaleController.getString("RestorePasswordNoEmailTitle", R.string.RestorePasswordNoEmailTitle));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRecoverView$vPB5KxmiovHt6bfyw0t3ITWoYMc
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$1$HloginActivity$LoginActivityRecoverView(dialogInterface, i);
                }
            });
            Dialog dialog = HloginActivity.this.showDialog(builder.create());
            if (dialog != null) {
                dialog.setCanceledOnTouchOutside(false);
                dialog.setCancelable(false);
            }
        }

        public /* synthetic */ void lambda$null$1$HloginActivity$LoginActivityRecoverView(DialogInterface dialogInterface, int i) {
            HloginActivity.this.setPage(6, true, new Bundle(), true);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean needBackButton() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onCancelPressed() {
            this.nextPressed = false;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public String getHeaderName() {
            return LocaleController.getString("LoginPassword", R.string.LoginPassword);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void setParams(Bundle params, boolean restore) {
            if (params == null) {
                return;
            }
            this.codeField.setText("");
            this.currentParams = params;
            String string = params.getString("email_unconfirmed_pattern");
            this.email_unconfirmed_pattern = string;
            this.cancelButton.setText(LocaleController.formatString("RestoreEmailTrouble", R.string.RestoreEmailTrouble, string));
            AndroidUtilities.showKeyboard(this.codeField);
            this.codeField.requestFocus();
        }

        private void onPasscodeError(boolean clear) {
            if (HloginActivity.this.getParentActivity() == null) {
                return;
            }
            Vibrator v = (Vibrator) HloginActivity.this.getParentActivity().getSystemService("vibrator");
            if (v != null) {
                v.vibrate(200L);
            }
            if (clear) {
                this.codeField.setText("");
            }
            AndroidUtilities.shakeView(this.confirmTextView, 2.0f, 0);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onNextPressed() {
            if (this.nextPressed) {
                return;
            }
            String oldPassword = this.codeField.getText().toString();
            if (oldPassword.length() == 0) {
                onPasscodeError(false);
                return;
            }
            this.nextPressed = true;
            String code = this.codeField.getText().toString();
            if (code.length() != 0) {
                HloginActivity.this.needShowProgress(0);
                TLRPC.TL_auth_recoverPassword req = new TLRPC.TL_auth_recoverPassword();
                req.code = code;
                ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRecoverView$DmiDWNw2HsswiG7vj9HHS1ZILjc
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$onNextPressed$5$HloginActivity$LoginActivityRecoverView(tLObject, tL_error);
                    }
                }, 10);
                return;
            }
            onPasscodeError(false);
        }

        public /* synthetic */ void lambda$onNextPressed$5$HloginActivity$LoginActivityRecoverView(final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRecoverView$Iqw3Y-eurmKl9yG0uzlupoPWxPk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$4$HloginActivity$LoginActivityRecoverView(response, error);
                }
            });
        }

        public /* synthetic */ void lambda$null$4$HloginActivity$LoginActivityRecoverView(final TLObject response, TLRPC.TL_error error) {
            String timeString;
            HloginActivity.this.needHideProgress(false);
            this.nextPressed = false;
            if (response instanceof TLRPC.TL_auth_authorization) {
                AlertDialog.Builder builder = new AlertDialog.Builder(HloginActivity.this.getParentActivity());
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRecoverView$WYreq3OjX_YCovOT3b1Ez3Bz8XQ
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$3$HloginActivity$LoginActivityRecoverView(response, dialogInterface, i);
                    }
                });
                builder.setMessage(LocaleController.getString("PasswordReset", R.string.PasswordReset));
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                Dialog dialog = HloginActivity.this.showDialog(builder.create());
                if (dialog != null) {
                    dialog.setCanceledOnTouchOutside(false);
                    dialog.setCancelable(false);
                    return;
                }
                return;
            }
            if (error.text.startsWith("CODE_INVALID")) {
                onPasscodeError(true);
                return;
            }
            if (!error.text.startsWith("FLOOD_WAIT")) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), error.text);
                return;
            }
            int time = Utilities.parseInt(error.text).intValue();
            if (time < 60) {
                timeString = LocaleController.formatPluralString("Seconds", time);
            } else {
                timeString = LocaleController.formatPluralString("Minutes", time / 60);
            }
            HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString));
        }

        public /* synthetic */ void lambda$null$3$HloginActivity$LoginActivityRecoverView(TLObject response, DialogInterface dialogInterface, int i) {
            HloginActivity.this.onAuthSuccess((TLRPC.TL_auth_authorization) response);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean onBackPressed(boolean force) {
            HloginActivity.this.needHideProgress(true);
            this.currentParams = null;
            this.nextPressed = false;
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onShow() {
            super.onShow();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRecoverView$IGLcpUKZuVyBlqpLwrUrD23s8U8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onShow$6$HloginActivity$LoginActivityRecoverView();
                }
            }, 100L);
        }

        public /* synthetic */ void lambda$onShow$6$HloginActivity$LoginActivityRecoverView() {
            EditTextBoldCursor editTextBoldCursor = this.codeField;
            if (editTextBoldCursor != null) {
                editTextBoldCursor.requestFocus();
                EditTextBoldCursor editTextBoldCursor2 = this.codeField;
                editTextBoldCursor2.setSelection(editTextBoldCursor2.length());
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void saveStateParams(Bundle bundle) {
            String code = this.codeField.getText().toString();
            if (code != null && code.length() != 0) {
                bundle.putString("recoveryview_code", code);
            }
            Bundle bundle2 = this.currentParams;
            if (bundle2 != null) {
                bundle.putBundle("recoveryview_params", bundle2);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void restoreStateParams(Bundle bundle) {
            Bundle bundle2 = bundle.getBundle("recoveryview_params");
            this.currentParams = bundle2;
            if (bundle2 != null) {
                setParams(bundle2, true);
            }
            String code = bundle.getString("recoveryview_code");
            if (code != null) {
                this.codeField.setText(code);
            }
        }
    }

    public class LoginActivityRegisterView extends SlideView implements ImageUpdater.ImageUpdaterDelegate {
        private TLRPC.FileLocation avatar;
        private AnimatorSet avatarAnimation;
        private TLRPC.FileLocation avatarBig;
        private AvatarDrawable avatarDrawable;
        private ImageView avatarEditor;
        private BackupImageView avatarImage;
        private View avatarOverlay;
        private RadialProgressView avatarProgressView;
        private boolean createAfterUpload;
        private Bundle currentParams;
        private EditTextBoldCursor firstNameField;
        private ImageUpdater imageUpdater;
        private EditTextBoldCursor lastNameField;
        private boolean nextPressed;
        private String phoneCode;
        private String phoneHash;
        private TextView privacyView;
        private String requestPhone;
        private TextView textView;
        private TLRPC.InputFile uploadedAvatar;
        private TextView wrongNumber;

        @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
        public /* synthetic */ void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> arrayList, boolean z, int i) {
            ImageUpdater.ImageUpdaterDelegate.CC.$default$didSelectPhotos(this, arrayList, z, i);
        }

        @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
        public /* synthetic */ String getInitialSearchString() {
            return ImageUpdater.ImageUpdaterDelegate.CC.$default$getInitialSearchString(this);
        }

        public class LinkSpan extends ClickableSpan {
            public LinkSpan() {
            }

            @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
            public void updateDrawState(TextPaint ds) {
                super.updateDrawState(ds);
                ds.setUnderlineText(false);
            }

            @Override // android.text.style.ClickableSpan
            public void onClick(View widget) {
                LoginActivityRegisterView.this.showTermsOfService(false);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void showTermsOfService(boolean needAccept) {
            if (HloginActivity.this.currentTermsOfService == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(HloginActivity.this.getParentActivity());
            builder.setTitle(LocaleController.getString("TermsOfService", R.string.TermsOfService));
            if (needAccept) {
                builder.setPositiveButton(LocaleController.getString("Accept", R.string.Accept), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$XUxQaH2idOpYXFtEXpbyCSvpSBk
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$showTermsOfService$0$HloginActivity$LoginActivityRegisterView(dialogInterface, i);
                    }
                });
                builder.setNegativeButton(LocaleController.getString("Decline", R.string.Decline), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$2PUiObj4dob4Zei0wq19Xo409Yg
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$showTermsOfService$3$HloginActivity$LoginActivityRegisterView(dialogInterface, i);
                    }
                });
            } else {
                builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
            }
            SpannableStringBuilder text = new SpannableStringBuilder(HloginActivity.this.currentTermsOfService.text);
            MessageObject.addEntitiesToText(text, HloginActivity.this.currentTermsOfService.entities, false, 0, false, false, false);
            builder.setMessage(text);
            HloginActivity.this.showDialog(builder.create());
        }

        public /* synthetic */ void lambda$showTermsOfService$0$HloginActivity$LoginActivityRegisterView(DialogInterface dialog, int which) {
            HloginActivity.this.currentTermsOfService.popup = false;
            onNextPressed();
        }

        public /* synthetic */ void lambda$showTermsOfService$3$HloginActivity$LoginActivityRegisterView(DialogInterface dialog, int which) {
            AlertDialog.Builder builder1 = new AlertDialog.Builder(HloginActivity.this.getParentActivity());
            builder1.setTitle(LocaleController.getString("TermsOfService", R.string.TermsOfService));
            builder1.setMessage(LocaleController.getString("TosDecline", R.string.TosDecline));
            builder1.setPositiveButton(LocaleController.getString("SignUp", R.string.SignUp), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$4FZFwPzH4d7bi2U43T7KexIAenI
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$1$HloginActivity$LoginActivityRegisterView(dialogInterface, i);
                }
            });
            builder1.setNegativeButton(LocaleController.getString("Decline", R.string.Decline), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$-hjV2va-ZvegAaIlK7exkAnts7w
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$2$HloginActivity$LoginActivityRegisterView(dialogInterface, i);
                }
            });
            HloginActivity.this.showDialog(builder1.create());
        }

        public /* synthetic */ void lambda$null$1$HloginActivity$LoginActivityRegisterView(DialogInterface dialog1, int which1) {
            HloginActivity.this.currentTermsOfService.popup = false;
            onNextPressed();
        }

        public /* synthetic */ void lambda$null$2$HloginActivity$LoginActivityRegisterView(DialogInterface dialog12, int which12) {
            onBackPressed(true);
            HloginActivity.this.setPage(0, true, null, true);
        }

        public LoginActivityRegisterView(Context context) {
            super(context);
            this.nextPressed = false;
            setOrientation(1);
            ImageUpdater imageUpdater = new ImageUpdater();
            this.imageUpdater = imageUpdater;
            imageUpdater.setSearchAvailable(false);
            this.imageUpdater.setUploadAfterSelect(false);
            this.imageUpdater.parentFragment = HloginActivity.this;
            this.imageUpdater.delegate = this;
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setText(LocaleController.getString("RegisterText2", R.string.RegisterText2));
            this.textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.textView.setGravity(LocaleController.isRTL ? 5 : 3);
            this.textView.setTextSize(1, 14.0f);
            addView(this.textView, LayoutHelper.createLinear(-2, -2, LocaleController.isRTL ? 5 : 3, 0, 0, 0, 0));
            FrameLayout editTextContainer = new FrameLayout(context);
            addView(editTextContainer, LayoutHelper.createLinear(-1, -2, 0.0f, 21.0f, 0.0f, 0.0f));
            this.avatarDrawable = new AvatarDrawable();
            BackupImageView backupImageView = new BackupImageView(context) { // from class: im.uwrkaxlmjj.ui.hui.login.HloginActivity.LoginActivityRegisterView.1
                @Override // android.view.View
                public void invalidate() {
                    if (LoginActivityRegisterView.this.avatarOverlay != null) {
                        LoginActivityRegisterView.this.avatarOverlay.invalidate();
                    }
                    super.invalidate();
                }

                @Override // android.view.View
                public void invalidate(int l, int t, int r, int b) {
                    if (LoginActivityRegisterView.this.avatarOverlay != null) {
                        LoginActivityRegisterView.this.avatarOverlay.invalidate();
                    }
                    super.invalidate(l, t, r, b);
                }
            };
            this.avatarImage = backupImageView;
            backupImageView.setRoundRadius(AndroidUtilities.dp(32.0f));
            this.avatarDrawable.setInfo(5, null, null);
            this.avatarImage.setImageDrawable(this.avatarDrawable);
            editTextContainer.addView(this.avatarImage, LayoutHelper.createFrame(64.0f, 64.0f, (LocaleController.isRTL ? 5 : 3) | 48, 0.0f, 16.0f, 0.0f, 0.0f));
            final Paint paint = new Paint(1);
            paint.setColor(1426063360);
            View view = new View(context) { // from class: im.uwrkaxlmjj.ui.hui.login.HloginActivity.LoginActivityRegisterView.2
                @Override // android.view.View
                protected void onDraw(Canvas canvas) {
                    if (LoginActivityRegisterView.this.avatarImage != null && LoginActivityRegisterView.this.avatarProgressView.getVisibility() == 0) {
                        paint.setAlpha((int) (LoginActivityRegisterView.this.avatarImage.getImageReceiver().getCurrentAlpha() * 85.0f * LoginActivityRegisterView.this.avatarProgressView.getAlpha()));
                        canvas.drawCircle(getMeasuredWidth() / 2, getMeasuredHeight() / 2, AndroidUtilities.dp(32.0f), paint);
                    }
                }
            };
            this.avatarOverlay = view;
            editTextContainer.addView(view, LayoutHelper.createFrame(64.0f, 64.0f, (LocaleController.isRTL ? 5 : 3) | 48, 0.0f, 16.0f, 0.0f, 0.0f));
            this.avatarOverlay.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$SbwEzn7Tp7R1syV7ITsXo3aNb6g
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$new$5$HloginActivity$LoginActivityRegisterView(view2);
                }
            });
            ImageView imageView = new ImageView(context) { // from class: im.uwrkaxlmjj.ui.hui.login.HloginActivity.LoginActivityRegisterView.3
                @Override // android.view.View
                public void invalidate(int l, int t, int r, int b) {
                    super.invalidate(l, t, r, b);
                    LoginActivityRegisterView.this.avatarOverlay.invalidate();
                }

                @Override // android.view.View
                public void invalidate() {
                    super.invalidate();
                    LoginActivityRegisterView.this.avatarOverlay.invalidate();
                }
            };
            this.avatarEditor = imageView;
            imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.avatarEditor.setImageResource(R.drawable.actions_setphoto);
            this.avatarEditor.setEnabled(false);
            this.avatarEditor.setClickable(false);
            this.avatarEditor.setPadding(AndroidUtilities.dp(2.0f), 0, 0, 0);
            editTextContainer.addView(this.avatarEditor, LayoutHelper.createFrame(64.0f, 64.0f, (LocaleController.isRTL ? 5 : 3) | 48, 0.0f, 16.0f, 0.0f, 0.0f));
            RadialProgressView radialProgressView = new RadialProgressView(context) { // from class: im.uwrkaxlmjj.ui.hui.login.HloginActivity.LoginActivityRegisterView.4
                @Override // im.uwrkaxlmjj.ui.components.RadialProgressView, android.view.View
                public void setAlpha(float alpha) {
                    super.setAlpha(alpha);
                    LoginActivityRegisterView.this.avatarOverlay.invalidate();
                }
            };
            this.avatarProgressView = radialProgressView;
            radialProgressView.setSize(AndroidUtilities.dp(30.0f));
            this.avatarProgressView.setProgressColor(-1);
            editTextContainer.addView(this.avatarProgressView, LayoutHelper.createFrame(64.0f, 64.0f, (LocaleController.isRTL ? 5 : 3) | 48, 0.0f, 16.0f, 0.0f, 0.0f));
            showAvatarProgress(false, false);
            EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(context);
            this.firstNameField = editTextBoldCursor;
            editTextBoldCursor.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
            this.firstNameField.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.firstNameField.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
            this.firstNameField.setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.firstNameField.setCursorSize(AndroidUtilities.dp(20.0f));
            this.firstNameField.setCursorWidth(1.5f);
            this.firstNameField.setHint(LocaleController.getString("FirstName", R.string.FirstName));
            this.firstNameField.setImeOptions(268435461);
            this.firstNameField.setTextSize(1, 17.0f);
            this.firstNameField.setMaxLines(1);
            this.firstNameField.setInputType(8192);
            editTextContainer.addView(this.firstNameField, LayoutHelper.createFrame(-1.0f, 36.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 0.0f : 85.0f, 0.0f, LocaleController.isRTL ? 85.0f : 0.0f, 0.0f));
            this.firstNameField.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$UzoTwnknBUHF4YKdmAlR8tQlicc
                @Override // android.widget.TextView.OnEditorActionListener
                public final boolean onEditorAction(TextView textView2, int i, KeyEvent keyEvent) {
                    return this.f$0.lambda$new$6$HloginActivity$LoginActivityRegisterView(textView2, i, keyEvent);
                }
            });
            EditTextBoldCursor editTextBoldCursor2 = new EditTextBoldCursor(context);
            this.lastNameField = editTextBoldCursor2;
            editTextBoldCursor2.setHint(LocaleController.getString("LastName", R.string.LastName));
            this.lastNameField.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
            this.lastNameField.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.lastNameField.setBackgroundDrawable(Theme.createEditTextDrawable(context, false));
            this.lastNameField.setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.lastNameField.setCursorSize(AndroidUtilities.dp(20.0f));
            this.lastNameField.setCursorWidth(1.5f);
            this.lastNameField.setImeOptions(268435462);
            this.lastNameField.setTextSize(1, 17.0f);
            this.lastNameField.setMaxLines(1);
            this.lastNameField.setInputType(8192);
            editTextContainer.addView(this.lastNameField, LayoutHelper.createFrame(-1.0f, 36.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 0.0f : 85.0f, 51.0f, LocaleController.isRTL ? 85.0f : 0.0f, 0.0f));
            this.lastNameField.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$6rjO0BOTU5I7ZOpYTtitmKoqxus
                @Override // android.widget.TextView.OnEditorActionListener
                public final boolean onEditorAction(TextView textView2, int i, KeyEvent keyEvent) {
                    return this.f$0.lambda$new$7$HloginActivity$LoginActivityRegisterView(textView2, i, keyEvent);
                }
            });
            TextView textView2 = new TextView(context);
            this.wrongNumber = textView2;
            textView2.setText(LocaleController.getString("CancelRegistration", R.string.CancelRegistration));
            this.wrongNumber.setGravity((LocaleController.isRTL ? 5 : 3) | 1);
            this.wrongNumber.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText4));
            this.wrongNumber.setTextSize(1, 14.0f);
            this.wrongNumber.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            this.wrongNumber.setPadding(0, AndroidUtilities.dp(24.0f), 0, 0);
            this.wrongNumber.setVisibility(8);
            addView(this.wrongNumber, LayoutHelper.createLinear(-2, -2, (LocaleController.isRTL ? 5 : 3) | 48, 0, 20, 0, 0));
            this.wrongNumber.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$4pltxh1vgmSMxDTvCpFgUAJLDSc
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$new$8$HloginActivity$LoginActivityRegisterView(view2);
                }
            });
            TextView textView3 = new TextView(context);
            this.privacyView = textView3;
            textView3.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.privacyView.setMovementMethod(new AndroidUtilities.LinkMovementMethodMy());
            this.privacyView.setLinkTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteLinkText));
            this.privacyView.setTextSize(1, 14.0f);
            this.privacyView.setGravity(81);
            this.privacyView.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            addView(this.privacyView, LayoutHelper.createLinear(-2, -1, 81, 0, 28, 0, 16));
            String str = LocaleController.getString("TermsOfServiceLogin", R.string.TermsOfServiceLogin);
            SpannableStringBuilder text = new SpannableStringBuilder(str);
            int index1 = str.indexOf(42);
            int index2 = str.lastIndexOf(42);
            if (index1 != -1 && index2 != -1 && index1 != index2) {
                text.replace(index2, index2 + 1, (CharSequence) "");
                text.replace(index1, index1 + 1, (CharSequence) "");
                text.setSpan(new LinkSpan(), index1, index2 - 1, 33);
            }
            this.privacyView.setText(text);
        }

        public /* synthetic */ void lambda$new$5$HloginActivity$LoginActivityRegisterView(View view) {
            this.imageUpdater.openMenu(this.avatar != null, new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$pD_-oE3QKtm8nyn0dKUBhhaS9uQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$4$HloginActivity$LoginActivityRegisterView();
                }
            });
        }

        public /* synthetic */ void lambda$null$4$HloginActivity$LoginActivityRegisterView() {
            this.avatar = null;
            this.avatarBig = null;
            this.uploadedAvatar = null;
            showAvatarProgress(false, true);
            this.avatarImage.setImage((ImageLocation) null, (String) null, this.avatarDrawable, (Object) null);
            this.avatarEditor.setImageResource(R.drawable.actions_setphoto);
        }

        public /* synthetic */ boolean lambda$new$6$HloginActivity$LoginActivityRegisterView(TextView textView, int i, KeyEvent keyEvent) {
            if (i == 5) {
                this.lastNameField.requestFocus();
                return true;
            }
            return false;
        }

        public /* synthetic */ boolean lambda$new$7$HloginActivity$LoginActivityRegisterView(TextView textView, int i, KeyEvent keyEvent) {
            if (i == 6 || i == 5) {
                onNextPressed();
                return true;
            }
            return false;
        }

        public /* synthetic */ void lambda$new$8$HloginActivity$LoginActivityRegisterView(View view) {
            if (HloginActivity.this.doneProgressView.getTag() != null) {
                return;
            }
            onBackPressed(false);
        }

        @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
        public void didUploadPhoto(TLRPC.InputFile file, final TLRPC.PhotoSize bigSize, final TLRPC.PhotoSize smallSize) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$bsy0DiOstuiZBG-rHnjsZ7tFKnE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$didUploadPhoto$9$HloginActivity$LoginActivityRegisterView(smallSize, bigSize);
                }
            });
        }

        public /* synthetic */ void lambda$didUploadPhoto$9$HloginActivity$LoginActivityRegisterView(TLRPC.PhotoSize smallSize, TLRPC.PhotoSize bigSize) {
            this.avatar = smallSize.location;
            this.avatarBig = bigSize.location;
            this.avatarImage.setImage(ImageLocation.getForLocal(this.avatar), "50_50", this.avatarDrawable, (Object) null);
        }

        private void showAvatarProgress(final boolean show, boolean animated) {
            if (this.avatarEditor == null) {
                return;
            }
            AnimatorSet animatorSet = this.avatarAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.avatarAnimation = null;
            }
            if (animated) {
                this.avatarAnimation = new AnimatorSet();
                if (show) {
                    this.avatarProgressView.setVisibility(0);
                    this.avatarAnimation.playTogether(ObjectAnimator.ofFloat(this.avatarEditor, (Property<ImageView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.avatarProgressView, (Property<RadialProgressView, Float>) View.ALPHA, 1.0f));
                } else {
                    this.avatarEditor.setVisibility(0);
                    this.avatarAnimation.playTogether(ObjectAnimator.ofFloat(this.avatarEditor, (Property<ImageView, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(this.avatarProgressView, (Property<RadialProgressView, Float>) View.ALPHA, 0.0f));
                }
                this.avatarAnimation.setDuration(180L);
                this.avatarAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.login.HloginActivity.LoginActivityRegisterView.5
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (LoginActivityRegisterView.this.avatarAnimation == null || LoginActivityRegisterView.this.avatarEditor == null) {
                            return;
                        }
                        if (show) {
                            LoginActivityRegisterView.this.avatarEditor.setVisibility(4);
                        } else {
                            LoginActivityRegisterView.this.avatarProgressView.setVisibility(4);
                        }
                        LoginActivityRegisterView.this.avatarAnimation = null;
                    }

                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationCancel(Animator animation) {
                        LoginActivityRegisterView.this.avatarAnimation = null;
                    }
                });
                this.avatarAnimation.start();
                return;
            }
            if (show) {
                this.avatarEditor.setAlpha(1.0f);
                this.avatarEditor.setVisibility(4);
                this.avatarProgressView.setAlpha(1.0f);
                this.avatarProgressView.setVisibility(0);
                return;
            }
            this.avatarEditor.setAlpha(1.0f);
            this.avatarEditor.setVisibility(0);
            this.avatarProgressView.setAlpha(0.0f);
            this.avatarProgressView.setVisibility(4);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean onBackPressed(boolean force) {
            if (!force) {
                AlertDialog.Builder builder = new AlertDialog.Builder(HloginActivity.this.getParentActivity());
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setMessage(LocaleController.getString("AreYouSureRegistration", R.string.AreYouSureRegistration));
                builder.setNegativeButton(LocaleController.getString("Stop", R.string.Stop), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$Z9AWaLI_IAUM4RQQP5W2CPADau4
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onBackPressed$10$HloginActivity$LoginActivityRegisterView(dialogInterface, i);
                    }
                });
                builder.setPositiveButton(LocaleController.getString("Continue", R.string.Continue), null);
                HloginActivity.this.showDialog(builder.create());
                return false;
            }
            HloginActivity.this.needHideProgress(true);
            this.nextPressed = false;
            this.currentParams = null;
            return true;
        }

        public /* synthetic */ void lambda$onBackPressed$10$HloginActivity$LoginActivityRegisterView(DialogInterface dialogInterface, int i) {
            onBackPressed(true);
            HloginActivity.this.setPage(0, true, null, true);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public String getHeaderName() {
            return LocaleController.getString("YourName", R.string.YourName);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onCancelPressed() {
            this.nextPressed = false;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean needBackButton() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onShow() {
            super.onShow();
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$m3JUqifOPYIfXJGlae2XUlxC060
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onShow$11$HloginActivity$LoginActivityRegisterView();
                }
            }, 100L);
        }

        public /* synthetic */ void lambda$onShow$11$HloginActivity$LoginActivityRegisterView() {
            EditTextBoldCursor editTextBoldCursor = this.firstNameField;
            if (editTextBoldCursor != null) {
                editTextBoldCursor.requestFocus();
                EditTextBoldCursor editTextBoldCursor2 = this.firstNameField;
                editTextBoldCursor2.setSelection(editTextBoldCursor2.length());
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void setParams(Bundle params, boolean restore) {
            if (params == null) {
                return;
            }
            this.firstNameField.setText("");
            this.lastNameField.setText("");
            this.requestPhone = params.getString("phoneFormated");
            this.phoneHash = params.getString("phoneHash");
            this.phoneCode = params.getString("code");
            this.currentParams = params;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onNextPressed() {
            if (!this.nextPressed) {
                if (HloginActivity.this.currentTermsOfService != null && HloginActivity.this.currentTermsOfService.popup) {
                    showTermsOfService(true);
                    return;
                }
                this.nextPressed = true;
                TLRPC.TL_auth_signUp req = new TLRPC.TL_auth_signUp();
                req.phone_code_hash = this.phoneHash;
                req.phone_number = this.requestPhone;
                req.first_name = this.firstNameField.getText().toString();
                req.last_name = this.lastNameField.getText().toString();
                HloginActivity.this.needShowProgress(0);
                ConnectionsManager.getInstance(HloginActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$wOC3mw8V0kTWnlmVgDsOrPz2QCM
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$onNextPressed$13$HloginActivity$LoginActivityRegisterView(tLObject, tL_error);
                    }
                }, 10);
            }
        }

        public /* synthetic */ void lambda$onNextPressed$13$HloginActivity$LoginActivityRegisterView(TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$HloginActivity$LoginActivityRegisterView$iLxw3HngXUbwD-Jbcwv3_r5zLpk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$12$HloginActivity$LoginActivityRegisterView(error);
                }
            });
        }

        public /* synthetic */ void lambda$null$12$HloginActivity$LoginActivityRegisterView(TLRPC.TL_error error) {
            this.nextPressed = false;
            HloginActivity.this.needHideProgress(false);
            if (TextUtils.isEmpty(this.firstNameField.getText().toString().trim())) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("EmptyNameTips", R.string.EmptyNameTips));
                return;
            }
            if (error.text.contains("PHONE_NUMBER_INVALID")) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("InvalidPhoneNumber", R.string.InvalidPhoneNumber));
                return;
            }
            if (error.text.contains("PHONE_CODE_EMPTY") || error.text.contains("PHONE_CODE_INVALID")) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("InvalidCode", R.string.InvalidCode));
                return;
            }
            if (error.text.contains("PHONE_CODE_EXPIRED")) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("CodeExpired", R.string.CodeExpired));
                return;
            }
            if (error.text.contains("FIRSTNAME_INVALID")) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("InvalidName", R.string.InvalidName));
                return;
            }
            if (error.text.contains("LASTNAME_INVALID")) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("InvalidNickname", R.string.InvalidNickname));
            } else if (error.text.contains("FIRSTNAME_LASTNAME_EMPTY")) {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), LocaleController.getString("EmptyNameTips", R.string.EmptyNameTips));
            } else {
                HloginActivity.this.needShowAlert(LocaleController.getString("AppName", R.string.AppName), error.text);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void saveStateParams(Bundle bundle) {
            String first = this.firstNameField.getText().toString();
            if (first.length() != 0) {
                bundle.putString("registerview_first", first);
            }
            String last = this.lastNameField.getText().toString();
            if (last.length() != 0) {
                bundle.putString("registerview_last", last);
            }
            if (HloginActivity.this.currentTermsOfService != null) {
                SerializedData data = new SerializedData(HloginActivity.this.currentTermsOfService.getObjectSize());
                HloginActivity.this.currentTermsOfService.serializeToStream(data);
                String str = Base64.encodeToString(data.toByteArray(), 0);
                bundle.putString("terms", str);
                data.cleanup();
            }
            Bundle bundle2 = this.currentParams;
            if (bundle2 != null) {
                bundle.putBundle("registerview_params", bundle2);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void restoreStateParams(Bundle bundle) {
            byte[] arr;
            Bundle bundle2 = bundle.getBundle("registerview_params");
            this.currentParams = bundle2;
            if (bundle2 != null) {
                setParams(bundle2, true);
            }
            try {
                String terms = bundle.getString("terms");
                if (terms != null && (arr = Base64.decode(terms, 0)) != null) {
                    SerializedData data = new SerializedData(arr);
                    HloginActivity.this.currentTermsOfService = TLRPC.TL_help_termsOfService.TLdeserialize(data, data.readInt32(false), false);
                    data.cleanup();
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
            String first = bundle.getString("registerview_first");
            if (first != null) {
                this.firstNameField.setText(first);
            }
            String last = bundle.getString("registerview_last");
            if (last != null) {
                this.lastNameField.setText(last);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        int a = 0;
        while (true) {
            SlideView[] slideViewArr = this.views;
            if (a < slideViewArr.length) {
                if (slideViewArr[a] != null) {
                    a++;
                } else {
                    return new ThemeDescription[0];
                }
            } else {
                PhoneView phoneView = (PhoneView) slideViewArr[0];
                LoginActivitySmsView smsView1 = (LoginActivitySmsView) slideViewArr[1];
                LoginActivitySmsView smsView2 = (LoginActivitySmsView) slideViewArr[2];
                LoginActivitySmsView smsView3 = (LoginActivitySmsView) slideViewArr[3];
                LoginActivitySmsView smsView4 = (LoginActivitySmsView) slideViewArr[4];
                LoginActivityRegisterView registerView = (LoginActivityRegisterView) slideViewArr[5];
                LoginActivityPasswordView passwordView = (LoginActivityPasswordView) slideViewArr[6];
                LoginActivityRecoverView recoverView = (LoginActivityRecoverView) slideViewArr[7];
                LoginActivityResetWaitView waitView = (LoginActivityResetWaitView) slideViewArr[8];
                ArrayList<ThemeDescription> arrayList = new ArrayList<>();
                arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite));
                arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault));
                arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault));
                arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon));
                arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle));
                arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector));
                arrayList.add(new ThemeDescription(phoneView.countryButton, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(phoneView.view, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhiteGrayLine));
                arrayList.add(new ThemeDescription(phoneView.textView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(phoneView.codeField, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(phoneView.codeField, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField));
                arrayList.add(new ThemeDescription(phoneView.codeField, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                arrayList.add(new ThemeDescription(phoneView.phoneField, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(phoneView.phoneField, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText));
                arrayList.add(new ThemeDescription(phoneView.phoneField, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField));
                arrayList.add(new ThemeDescription(phoneView.phoneField, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                arrayList.add(new ThemeDescription(phoneView.textView2, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(passwordView.confirmTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(passwordView.codeField, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(passwordView.codeField, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText));
                arrayList.add(new ThemeDescription(passwordView.codeField, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField));
                arrayList.add(new ThemeDescription(passwordView.codeField, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                arrayList.add(new ThemeDescription(passwordView.cancelButton, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText4));
                arrayList.add(new ThemeDescription(passwordView.resetAccountButton, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteRedText6));
                arrayList.add(new ThemeDescription(passwordView.resetAccountText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(registerView.textView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(registerView.firstNameField, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText));
                arrayList.add(new ThemeDescription(registerView.firstNameField, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(registerView.firstNameField, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField));
                arrayList.add(new ThemeDescription(registerView.firstNameField, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                arrayList.add(new ThemeDescription(registerView.lastNameField, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText));
                arrayList.add(new ThemeDescription(registerView.lastNameField, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(registerView.lastNameField, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField));
                arrayList.add(new ThemeDescription(registerView.lastNameField, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                arrayList.add(new ThemeDescription(registerView.wrongNumber, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText4));
                arrayList.add(new ThemeDescription(registerView.privacyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(registerView.privacyView, ThemeDescription.FLAG_LINKCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteLinkText));
                arrayList.add(new ThemeDescription(recoverView.confirmTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(recoverView.codeField, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(recoverView.codeField, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText));
                arrayList.add(new ThemeDescription(recoverView.codeField, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField));
                arrayList.add(new ThemeDescription(recoverView.codeField, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                arrayList.add(new ThemeDescription(recoverView.cancelButton, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText4));
                arrayList.add(new ThemeDescription(waitView.confirmTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(waitView.resetAccountText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(waitView.resetAccountTime, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(waitView.resetAccountButton, ThemeDescription.FLAG_CHECKTAG | ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(waitView.resetAccountButton, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, null, null, null, null, Theme.key_windowBackgroundWhiteRedText6));
                arrayList.add(new ThemeDescription(smsView1.confirmTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(smsView1.titleTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                if (smsView1.codeField != null) {
                    for (int a2 = 0; a2 < smsView1.codeField.length; a2++) {
                        arrayList.add(new ThemeDescription(smsView1.codeField[a2], ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                        arrayList.add(new ThemeDescription(smsView1.codeField[a2], ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                    }
                }
                arrayList.add(new ThemeDescription(smsView1.timeText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(smsView1.problemText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText4));
                arrayList.add(new ThemeDescription(smsView1.progressView, 0, new Class[]{ProgressView.class}, new String[]{"paint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_login_progressInner));
                arrayList.add(new ThemeDescription(smsView1.progressView, 0, new Class[]{ProgressView.class}, new String[]{"paint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_login_progressOuter));
                arrayList.add(new ThemeDescription(smsView1.blackImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(smsView1.blueImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chats_actionBackground));
                arrayList.add(new ThemeDescription(smsView2.confirmTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(smsView2.titleTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                if (smsView2.codeField != null) {
                    for (int a3 = 0; a3 < smsView2.codeField.length; a3++) {
                        arrayList.add(new ThemeDescription(smsView2.codeField[a3], ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                        arrayList.add(new ThemeDescription(smsView2.codeField[a3], ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                    }
                }
                arrayList.add(new ThemeDescription(smsView2.timeText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(smsView2.problemText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText4));
                arrayList.add(new ThemeDescription(smsView2.progressView, 0, new Class[]{ProgressView.class}, new String[]{"paint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_login_progressInner));
                arrayList.add(new ThemeDescription(smsView2.progressView, 0, new Class[]{ProgressView.class}, new String[]{"paint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_login_progressOuter));
                arrayList.add(new ThemeDescription(smsView2.blackImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(smsView2.blueImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chats_actionBackground));
                arrayList.add(new ThemeDescription(smsView3.confirmTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(smsView3.titleTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                if (smsView3.codeField != null) {
                    for (int a4 = 0; a4 < smsView3.codeField.length; a4++) {
                        arrayList.add(new ThemeDescription(smsView3.codeField[a4], ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                        arrayList.add(new ThemeDescription(smsView3.codeField[a4], ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                    }
                }
                arrayList.add(new ThemeDescription(smsView3.timeText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(smsView3.problemText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText4));
                arrayList.add(new ThemeDescription(smsView3.progressView, 0, new Class[]{ProgressView.class}, new String[]{"paint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_login_progressInner));
                arrayList.add(new ThemeDescription(smsView3.progressView, 0, new Class[]{ProgressView.class}, new String[]{"paint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_login_progressOuter));
                arrayList.add(new ThemeDescription(smsView3.blackImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(smsView3.blueImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chats_actionBackground));
                arrayList.add(new ThemeDescription(smsView4.confirmTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(smsView4.titleTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                if (smsView4.codeField != null) {
                    for (int a5 = 0; a5 < smsView4.codeField.length; a5++) {
                        arrayList.add(new ThemeDescription(smsView4.codeField[a5], ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                        arrayList.add(new ThemeDescription(smsView4.codeField[a5], ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                    }
                }
                arrayList.add(new ThemeDescription(smsView4.timeText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText6));
                arrayList.add(new ThemeDescription(smsView4.problemText, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText4));
                arrayList.add(new ThemeDescription(smsView4.progressView, 0, new Class[]{ProgressView.class}, new String[]{"paint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_login_progressInner));
                arrayList.add(new ThemeDescription(smsView4.progressView, 0, new Class[]{ProgressView.class}, new String[]{"paint"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_login_progressOuter));
                arrayList.add(new ThemeDescription(smsView4.blackImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(smsView4.blueImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chats_actionBackground));
                return (ThemeDescription[]) arrayList.toArray(new ThemeDescription[0]);
            }
        }
    }
}
