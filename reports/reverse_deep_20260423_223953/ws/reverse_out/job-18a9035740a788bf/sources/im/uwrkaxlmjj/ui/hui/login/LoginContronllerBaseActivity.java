package im.uwrkaxlmjj.ui.hui.login;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.graphics.Rect;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Property;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.Unbinder;
import butterknife.internal.Utils;
import com.blankj.utilcode.util.ScreenUtils;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.RegexUtils;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.SlideView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.utils.KeyboardChangeListener;
import im.uwrkaxlmjj.ui.utils.timer.RunningFlagCountDownTimer;
import java.util.Locale;
import java.util.regex.Pattern;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public abstract class LoginContronllerBaseActivity extends BaseFragment implements KeyboardChangeListener.KeyBoardListener {
    public static final String REGEX_USERNAME = "^\\w{5,32}(?<!_)$";
    protected FrameLayout actionBarContainer;
    protected boolean canBack;
    protected FrameLayout contentContainer;
    protected int currentViewIndex;
    protected boolean keyboardIsShown;
    protected KeyboardChangeListener mKeyboardChangeListener;
    protected boolean newAccount;
    protected ThisView[] pages;
    protected FrameLayout rootView;

    protected abstract void initPages(int i);

    protected abstract void initView();

    public class ThisView_ViewBinding implements Unbinder {
        private ThisView target;

        public ThisView_ViewBinding(ThisView target) {
            this(target, target);
        }

        public ThisView_ViewBinding(ThisView target, View source) {
            this.target = target;
            target.btn = (MryRoundButton) Utils.findRequiredViewAsType(source, R.attr.btn, "field 'btn'", MryRoundButton.class);
        }

        @Override // butterknife.Unbinder
        public void unbind() {
            ThisView target = this.target;
            if (target == null) {
                throw new IllegalStateException("Bindings already cleared.");
            }
            this.target = null;
            target.btn = null;
        }
    }

    public LoginContronllerBaseActivity() {
        this(UserConfig.selectedAccount, null);
    }

    public LoginContronllerBaseActivity(int account, Bundle args) {
        this.canBack = true;
        args = args == null ? new Bundle() : args;
        args.putInt("account", account);
        args.putBoolean("newAccount", account != UserConfig.selectedAccount);
        setArguments(args);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        if (getArguments() != null) {
            this.currentAccount = getArguments().getInt("account");
            this.newAccount = getArguments().getBoolean("newAccount", false);
            boolean z = getArguments().getBoolean("canBack", true);
            this.canBack = z;
            if (z) {
                int hasCount = 0;
                for (int i = 0; i < 3; i++) {
                    if (!UserConfig.getInstance(i).isClientActivated()) {
                        hasCount++;
                    }
                }
                if (hasCount == 3) {
                    this.canBack = false;
                }
            }
        }
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.rootView = new FrameLayout(context);
        ScrollView scrollView = new ScrollView(context) { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.1
            @Override // android.widget.ScrollView, android.view.ViewGroup, android.view.ViewParent
            public boolean requestChildRectangleOnScreen(View child, Rect rectangle, boolean immediate) {
                rectangle.bottom += AndroidUtilities.dp(40.0f);
                return super.requestChildRectangleOnScreen(child, rectangle, immediate);
            }
        };
        scrollView.setFillViewport(true);
        this.fragmentView = this.rootView;
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.rootView.addView(scrollView, LayoutHelper.createScroll(-1, -1, 51));
        KeyboardChangeListener keyboardChangeListener = new KeyboardChangeListener(scrollView);
        this.mKeyboardChangeListener = keyboardChangeListener;
        keyboardChangeListener.setKeyBoardListener(this);
        FrameLayout frameLayout = new FrameLayout(context);
        this.contentContainer = frameLayout;
        scrollView.addView(frameLayout, LayoutHelper.createFrame(-1, -1, 51));
        initActionBar();
        initView();
        return this.fragmentView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        if (this.newAccount) {
            ConnectionsManager.getInstance(this.currentAccount).setAppPaused(false, false);
        }
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        AndroidUtilities.removeAdjustResize(getParentActivity(), this.classGuid);
        if (this.newAccount) {
            ConnectionsManager.getInstance(this.currentAccount).setAppPaused(true, false);
        }
    }

    protected void initActionBar() {
        this.actionBar.setAddToContainer(false);
        this.actionBar.setBackgroundColor(0);
        this.actionBar.setCastShadows(false);
        FrameLayout frameLayout = new FrameLayout(getParentActivity());
        this.actionBarContainer = frameLayout;
        frameLayout.setBackgroundColor(0);
        this.rootView.addView(this.actionBarContainer, LayoutHelper.createFrame(-1, -2, 51));
        this.actionBarContainer.addView(this.actionBar, LayoutHelper.createFrame(-1, -2, 51));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                super.onItemClick(id);
                if (id == -1 && LoginContronllerBaseActivity.this.onBackPressed()) {
                    LoginContronllerBaseActivity.this.finishFragment();
                }
            }
        });
    }

    protected void setAcitonBar(int newPageIndex, ThisView thisView) {
        if (this.canBack) {
            this.actionBar.setBackButtonImage((thisView.needBackButton() || this.newAccount) ? R.id.ic_back : 0);
        }
    }

    protected final void toPage(int newPageIndex, boolean animated, Bundle params, boolean back) {
        initPages(newPageIndex);
        ThisView[] thisViewArr = this.pages;
        if (thisViewArr[newPageIndex] == null) {
            return;
        }
        if (this.currentViewIndex == newPageIndex && thisViewArr[newPageIndex].getParent() != null) {
            this.pages[this.currentViewIndex].setParams(params, false);
            return;
        }
        if (this.pages[newPageIndex].getParent() == null) {
            this.contentContainer.addView(this.pages[newPageIndex], LayoutHelper.createFrame(-1, -1, 51));
        }
        if (animated) {
            ThisView[] thisViewArr2 = this.pages;
            final ThisView outView = thisViewArr2[this.currentViewIndex];
            final ThisView newView = thisViewArr2[newPageIndex];
            newView.setClickable(true);
            this.currentViewIndex = newPageIndex;
            newView.setParams(params, false);
            setParentActivityTitle(newView.getHeaderName());
            setAcitonBar(newPageIndex, newView);
            newView.onShow();
            int i = AndroidUtilities.displaySize.x;
            if (back) {
                i = -i;
            }
            newView.setX(i);
            newView.setVisibility(0);
            AnimatorSet animatorSet = new AnimatorSet();
            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.3
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    outView.clearFocus();
                    outView.setVisibility(8);
                    outView.setX(0.0f);
                    newView.onShowEnd();
                }
            });
            Animator[] animatorArr = new Animator[2];
            Property property = View.TRANSLATION_X;
            float[] fArr = new float[1];
            int i2 = AndroidUtilities.displaySize.x;
            if (!back) {
                i2 = -i2;
            }
            fArr[0] = i2;
            animatorArr[0] = ObjectAnimator.ofFloat(outView, (Property<ThisView, Float>) property, fArr);
            animatorArr[1] = ObjectAnimator.ofFloat(newView, (Property<ThisView, Float>) View.TRANSLATION_X, 0.0f);
            animatorSet.playTogether(animatorArr);
            animatorSet.setDuration(300L);
            animatorSet.setInterpolator(new AccelerateDecelerateInterpolator());
            animatorSet.start();
            return;
        }
        this.pages[this.currentViewIndex].setVisibility(8);
        this.currentViewIndex = newPageIndex;
        this.pages[newPageIndex].setParams(params, false);
        this.pages[newPageIndex].setVisibility(0);
        this.pages[newPageIndex].onShow();
        this.pages[newPageIndex].onShowEnd();
        setAcitonBar(newPageIndex, this.pages[newPageIndex]);
        setParentActivityTitle(this.pages[newPageIndex].getHeaderName());
        this.pages[newPageIndex].onShow();
    }

    protected void parseError(TLRPC.TL_error error, String extra) {
        if (error != null && !TextUtils.isEmpty(error.text)) {
            if (error.text.contains("PHONE_NUMBER_INVALID")) {
                needShowInvalidAlert(extra, false);
                return;
            }
            if (error.text.contains("PHONE_PASSWORD_FLOOD")) {
                needShowAlert(LocaleController.getString(R.string.FloodWait));
                return;
            }
            if (error.text.contains("PHONE_NUMBER_FLOOD")) {
                needShowAlert(LocaleController.getString(R.string.PhoneNumberFlood));
                return;
            }
            if (error.text.contains("PHONE_NUMBER_BANNED") || error.text.contains("ACCOUNT_RESTRICTED") || error.text.contains("ACCOUNT_BLOCKED")) {
                needShowInvalidAlert(extra, true);
                return;
            }
            if (error.text.contains("PHONE_CODE_EMPTY") || error.text.contains("PHONE_CODE_INVALID")) {
                needShowAlert(LocaleController.getString("InvalidCode", R.string.InvalidCode));
                return;
            }
            if (error.text.contains("PHONE_CODE_EXPIRED")) {
                needShowAlert(LocaleController.getString("VerificationcodeExpired", R.string.VerificationcodeExpired));
                return;
            }
            if (error.text.startsWith("FLOOD_WAIT")) {
                needShowAlert(LocaleController.getString(R.string.FloodWait));
                return;
            }
            if (error.text.startsWith("CODE_VERIFY_LIMIT")) {
                needShowAlert(LocaleController.getString(R.string.CODE_VERIFY_LIMIT));
                return;
            }
            if (error.text.startsWith("CODE_INVALID")) {
                needShowAlert(LocaleController.getString(R.string.InvalidCode));
                return;
            }
            if (error.text.startsWith("PASSWORD_ERROR")) {
                needShowAlert(LocaleController.getString(R.string.LoginPwdError));
                return;
            }
            if (error.text.startsWith("PHONE_NOT_SIGNUP") || error.text.startsWith("USERNAME_NOT_EXIST")) {
                needShowAlert(LocaleController.getString(R.string.UserNotRegistered));
                return;
            }
            if (error.text.startsWith("PHONE_NUMBER_OCCUPIED")) {
                needShowAlert(LocaleController.getString(R.string.UsernameAlreadyExists));
                return;
            }
            if (error.text.startsWith("CURRENT_PWD_ERR")) {
                needShowAlert(LocaleController.getString(R.string.OldPwdError));
                return;
            }
            if (error.text.startsWith("NOTEQUAL_TAG")) {
                needShowAlert(LocaleController.getString(R.string.LoginPwdError));
                return;
            }
            if (error.text.startsWith("PASSWORD_INVALID")) {
                needShowAlert(LocaleController.getString(R.string.PasswordDoNotMatch));
                return;
            }
            if (error.text.startsWith("PASSWORD_MANY")) {
                needShowAlert(LocaleController.getString(R.string.PWdErrorMany));
                return;
            }
            if (error.text.startsWith("USERNAME_INVALID")) {
                needShowAlert(LocaleController.getString(R.string.UsernameInvalid));
                return;
            }
            if (error.text.startsWith("USERNAME_OCCUPIED")) {
                needShowAlert(LocaleController.getString(R.string.UsernameInUse));
                return;
            }
            if (error.text.contains("IPORDE_LIMIT")) {
                needShowAlert(LocaleController.getString("IpOrDeLimit", R.string.IpOrDeLimit));
                return;
            }
            if (error.text.equals("INTERNAL")) {
                needShowAlert(LocaleController.getString("InternalError", R.string.InternalError));
                return;
            }
            if (error.text.startsWith("GOOGLE_KEY_ERROR")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.GOOGLEKEYERROR));
                return;
            }
            if (error.text.equals("SINGLE_LIMIT")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.SINGLE_LIMIT));
                return;
            }
            if (error.text.equals("WHITENULL")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.WHITENULL));
                return;
            }
            if (error.text.equals("NOTENQUALIP")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.NOTENQUALIP));
                return;
            }
            if (error.text.equals("OLD_VERSION_RESTRICT")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.OLD_VERSION_RESTRICT));
                return;
            }
            if (error.text.equals("IP_BLOCKED")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.IP_BLOCKED));
                return;
            }
            if (error.text.equals("FLOOD_WAIT_60")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.FLOOD_WAIT_60));
                return;
            }
            if (error.text.equals("TYPE_CAST_ERROR")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.TYPE_CAST_ERROR));
                return;
            }
            if (error.text.equals("IP_SPEED_LIMIT")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.IP_SPEED_LIMIT));
                return;
            }
            if (error.text.equals("RPC_FAIL")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.RPC_FAIL));
                return;
            }
            if (error.text.equals("INTERNAL_ERROR") || error.text.equals("INTERNAL_ERRORO")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.INTERNAL_ERROR));
                return;
            }
            if (error.text.equals("USERDELETE")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.USERDELETE));
                return;
            }
            if (error.text.equals("NOT_ENGOGH")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.NOT_ENGOGH));
                return;
            }
            if (error.text.equals("UNKNOWN_SOURCE_BLOCKED")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.UNKNOWN_SOURCE_BLOCKED));
                return;
            }
            if (error.text.equals("NAME_TOO_LONG")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.NAME_TOO_LONG));
                return;
            }
            if (error.text.equals("InvalidName")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.InvalidNames));
                return;
            }
            if (error.text.equals("PROXYCODE_INVALID")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.PROXYCODE_INVALID));
                return;
            }
            if (error.text.equals("AUTH_CODE_APPLY_AGAIN")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.AUTH_CODE_APPLY_AGAIN));
                return;
            }
            if (error.text.equals("AUTH_CODE_APPLY_ALREADY")) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.AUTH_CODE_APPLY_ALREADY));
                return;
            }
            needShowAlert(LocaleController.getString(R.string.OperationFailedPleaseTryAgain) + ShellAdbUtils.COMMAND_LINE_END + error.text);
        }
    }

    protected void needShowInvalidAlert(final String phoneNumber, final boolean banned) {
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString(R.string.AppName));
        if (banned) {
            builder.setMessage(LocaleController.getString(R.string.BannedPhoneNumber));
        } else {
            builder.setMessage(LocaleController.getString(R.string.InvalidPhoneNumber));
        }
        builder.setNeutralButton(LocaleController.getString(R.string.BotHelp), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerBaseActivity$fnL2rXeyIxMl5Ac2l2pr_rMv0cA
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$needShowInvalidAlert$0$LoginContronllerBaseActivity(banned, phoneNumber, dialogInterface, i);
            }
        });
        builder.setPositiveButton(LocaleController.getString(R.string.OK), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$needShowInvalidAlert$0$LoginContronllerBaseActivity(boolean banned, String phoneNumber, DialogInterface dialog, int which) {
        try {
            PackageInfo pInfo = ApplicationLoader.applicationContext.getPackageManager().getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0);
            String version = String.format(Locale.US, "%s (%d)", pInfo.versionName, Integer.valueOf(pInfo.versionCode));
            Intent mailer = new Intent("android.intent.action.SEND");
            mailer.setType("message/rfc822");
            mailer.putExtra("android.intent.extra.EMAIL", new String[]{"login@stel.com"});
            if (banned) {
                mailer.putExtra("android.intent.extra.SUBJECT", "Banned phone number: " + phoneNumber);
                mailer.putExtra("android.intent.extra.TEXT", "I'm trying to use my mobile phone number: " + phoneNumber + "\nBut uwrkaxlmjj says it's banned. Please help.\n\nApp version: " + version + "\nOS version: SDK " + Build.VERSION.SDK_INT + "\nDevice Name: " + Build.MANUFACTURER + Build.MODEL + "\nLocale: " + Locale.getDefault());
            } else {
                mailer.putExtra("android.intent.extra.SUBJECT", "Invalid phone number: " + phoneNumber);
                mailer.putExtra("android.intent.extra.TEXT", "I'm trying to use my mobile phone number: " + phoneNumber + "\nBut uwrkaxlmjj says it's invalid. Please help.\n\nApp version: " + version + "\nOS version: SDK " + Build.VERSION.SDK_INT + "\nDevice Name: " + Build.MANUFACTURER + Build.MODEL + "\nLocale: " + Locale.getDefault());
            }
            getParentActivity().startActivity(Intent.createChooser(mailer, "Send email..."));
        } catch (Exception e) {
            needShowAlert(LocaleController.getString(R.string.NoMailInstalled));
        }
    }

    protected void needShowAlert(String text) {
        if (text == null || getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString(R.string.AppName));
        builder.setMessage(text);
        builder.setPositiveButton(LocaleController.getString(R.string.OK), null);
        showDialog(builder.create());
    }

    protected boolean checkPasswordRule(TextView et, boolean showErrorToast) {
        if (et == null || et.length() == 0) {
            return false;
        }
        String input = et.getText().toString().trim();
        if (input.length() < 8 || input.length() > 16) {
            if (showErrorToast) {
                ToastUtils.show(R.string.LoginPwdRule);
            }
            return false;
        }
        return true;
    }

    protected boolean checkPasswordRule(String input) {
        return !TextUtils.isEmpty(input) && input.length() >= 8 && input.length() <= 16;
    }

    protected boolean checkUserNameRule(String input) {
        return !TextUtils.isEmpty(input) && input.length() >= 5 && input.length() <= 32 && RegexUtils.firstLetterIsEnglishLetter(input) && isUserName(input);
    }

    public static boolean isUserName(CharSequence str) {
        if (str != null && str.length() > 0) {
            return Pattern.compile(REGEX_USERNAME).matcher(str).matches();
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle args) {
        super.saveSelfArgs(args);
        args.putInt("currentIndex", this.currentViewIndex);
        args.putBundle("pageArgs", getArguments());
        Bundle bundle = new Bundle();
        if (this.pages != null) {
            int i = 0;
            while (true) {
                ThisView[] thisViewArr = this.pages;
                if (i < thisViewArr.length) {
                    ThisView t = thisViewArr[i];
                    if (t != null) {
                        t.saveStateParams(bundle);
                        args.putBundle("currentIndexB" + i, bundle);
                    }
                    i++;
                } else {
                    return;
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void restoreSelfArgs(Bundle args) {
        super.restoreSelfArgs(args);
        this.currentViewIndex = args.getInt("currentIndex");
        setArguments(args.getBundle("pageArgs"));
        if (this.pages != null) {
            int i = 0;
            while (true) {
                ThisView[] thisViewArr = this.pages;
                if (i < thisViewArr.length) {
                    ThisView t = thisViewArr[i];
                    Bundle bundle = args.getBundle("currentIndexB" + i);
                    t.restoreStateParams(bundle);
                    i++;
                } else {
                    return;
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        ThisView[] thisViewArr = this.pages;
        if (thisViewArr != null) {
            int i = this.currentViewIndex;
            if (i == 0) {
                if (this.canBack) {
                    for (ThisView v : thisViewArr) {
                        if (v != null) {
                            v.onDestroyActivity();
                        }
                    }
                    return true;
                }
            } else if (i == 1) {
                thisViewArr[i].onBackPressed(true);
                toPage(0, true, null, true);
            } else if (i == 2) {
                thisViewArr[i].onBackPressed(true);
                toPage(1, true, null, true);
            }
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.utils.KeyboardChangeListener.KeyBoardListener
    public void onKeyboardChange(boolean isShow, int keyboardHeight) {
        int height;
        this.keyboardIsShown = isShow;
        View btn = this.pages[this.currentViewIndex].btn;
        if (!isFinishing() && btn != null && this.actionBar != null && isShow && (this.fragmentView instanceof ScrollView)) {
            int fb = ScreenUtils.getScreenHeight();
            int bgnb = btn.getBottom();
            int height2 = (AndroidUtilities.dp(10.0f) + keyboardHeight) - (fb - bgnb);
            if (this.newAccount) {
                height = (this.actionBar != null ? this.actionBar.getHeight() : 0) + height2;
            } else {
                height = height2;
            }
            ((ScrollView) this.fragmentView).smoothScrollBy(0, height);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        ThisView[] thisViewArr = this.pages;
        if (thisViewArr != null) {
            for (ThisView page : thisViewArr) {
                if (page != null) {
                    page.onDestroyActivity();
                }
            }
            this.pages = null;
        }
        KeyboardChangeListener keyboardChangeListener = this.mKeyboardChangeListener;
        if (keyboardChangeListener != null) {
            keyboardChangeListener.destroy();
            this.mKeyboardChangeListener = null;
        }
        this.rootView = null;
    }

    public static class ThisView extends SlideView {

        @BindView(R.attr.btn)
        MryRoundButton btn;
        protected RunningFlagCountDownTimer countDownTimer;
        protected Bundle params;
        private Unbinder unbinder;

        public ThisView(Context context) {
            super(context);
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void setParams(Bundle params, boolean restore) {
            super.setParams(params, restore);
            if (params != null) {
                this.params = params;
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public Bundle getParams() {
            return this.params;
        }

        protected void initView() {
            this.unbinder = ButterKnife.bind(this, this);
            this.btn.setPrimaryRadiusAdjustBoundsFillStyle();
            loadSaveState();
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onShow() {
            super.onShow();
        }

        protected void onShowEnd() {
            setClickable(true);
        }

        protected boolean checkEnterInfo(boolean sendSmsCode, boolean showErrorToast, boolean toNextStep) {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean needBackButton() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void saveStateParams(Bundle bundle) {
            super.saveStateParams(bundle);
        }

        protected SharedPreferences getSp() {
            return ApplicationLoader.applicationContext.getSharedPreferences("logininfo2", 0);
        }

        protected void loadSaveState() {
            SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("logininfo2", 0);
            long mills = preferences.getLong("countDownTimer", 0L);
            if (mills > 0) {
                startCountDownTimer(mills);
            }
        }

        protected void saveLastSendSmsTime() {
            SharedPreferences.Editor editor = getSp().edit();
            editor.putLong("last_time", System.currentTimeMillis());
            editor.apply();
        }

        protected long getLastSendSmsTime() {
            return getSp().getLong("last_time", 0L);
        }

        protected void startCountDownTimer(long countDownMills) {
            if (this.countDownTimer == null) {
                RunningFlagCountDownTimer runningFlagCountDownTimer = new RunningFlagCountDownTimer(countDownMills, 1000L) { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView.1
                    @Override // im.uwrkaxlmjj.ui.utils.timer.RunningFlagCountDownTimer, android.os.CountDownTimer
                    public void onTick(long millisUntilFinished) {
                        super.onTick(millisUntilFinished);
                        ThisView.this.onTimerTick(millisUntilFinished);
                    }

                    @Override // im.uwrkaxlmjj.ui.utils.timer.RunningFlagCountDownTimer, android.os.CountDownTimer
                    public void onFinish() {
                        super.onFinish();
                        ThisView.this.onTimerFinish();
                    }
                };
                this.countDownTimer = runningFlagCountDownTimer;
                runningFlagCountDownTimer.startInternal();
            }
        }

        protected void onTimerTick(long millisUntilFinished) {
            MryRoundButton mryRoundButton = this.btn;
            if (mryRoundButton != null) {
                mryRoundButton.setText(LocaleController.formatString("ResendPhoneCodeCountDown2", R.string.ResendPhoneCodeCountDown2, Long.valueOf(millisUntilFinished / 1000)));
                this.btn.setEnabled(false);
            }
        }

        protected void onTimerFinish() {
            MryRoundButton mryRoundButton = this.btn;
            if (mryRoundButton != null) {
                mryRoundButton.setText(LocaleController.getString(R.string.SendVerifyCode));
                this.btn.setEnabled(true);
            }
        }

        protected void stopTimer() {
            try {
                if (this.countDownTimer != null && this.countDownTimer.isRunning()) {
                    this.countDownTimer.cancelInternal();
                    this.countDownTimer = null;
                }
            } catch (Exception e) {
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onDestroyActivity() {
            super.onDestroyActivity();
            stopTimer();
            Unbinder unbinder = this.unbinder;
            if (unbinder != null) {
                try {
                    unbinder.unbind();
                } catch (Exception e) {
                }
                this.unbinder = null;
            }
            this.params = null;
        }
    }
}
