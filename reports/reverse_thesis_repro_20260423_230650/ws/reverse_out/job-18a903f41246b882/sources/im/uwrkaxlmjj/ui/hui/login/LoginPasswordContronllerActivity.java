package im.uwrkaxlmjj.ui.hui.login;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import butterknife.BindView;
import butterknife.OnClick;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.status.StatusBarUtils;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCLogin;
import im.uwrkaxlmjj.translate.MD5;
import im.uwrkaxlmjj.ui.IndexActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity;
import im.uwrkaxlmjj.ui.hviews.MryAlphaImageView;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class LoginPasswordContronllerActivity extends LoginContronllerBaseActivity implements NotificationCenter.NotificationCenterDelegate {
    public static final int PASSWORD_MODOIFY = 1;
    public static final int PASSWORD_RESET = 0;
    public static final int PASSWORD_SET = 2;
    public TextView backupIpAddressLog;
    private int contronllerType;

    public class StepThree_ViewBinding extends LoginContronllerBaseActivity.ThisView_ViewBinding {
        private StepThree target;
        private View view7f090097;
        private View view7f0901d0;
        private View view7f0901d1;
        private View view7f0901d2;
        private View view7f0901f4;
        private View view7f0901f5;
        private View view7f0901f6;

        public StepThree_ViewBinding(StepThree target) {
            this(target, target);
        }

        public StepThree_ViewBinding(final StepThree target, View source) {
            super(target, source);
            this.target = target;
            target.etPwd1Parent = Utils.findRequiredView(source, R.attr.etPwd1Parent, "field 'etPwd1Parent'");
            target.etPwd1 = (MryEditText) Utils.findRequiredViewAsType(source, R.attr.etPwd1, "field 'etPwd1'", MryEditText.class);
            View view = Utils.findRequiredView(source, R.attr.ivClear1, "field 'ivClear1' and method 'onClick'");
            target.ivClear1 = (MryAlphaImageView) Utils.castView(view, R.attr.ivClear1, "field 'ivClear1'", MryAlphaImageView.class);
            this.view7f0901d0 = view;
            view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity.StepThree_ViewBinding.1
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            View view2 = Utils.findRequiredView(source, R.attr.ivPwdShow1, "field 'ivPwdShow1' and method 'onClick'");
            target.ivPwdShow1 = (MryAlphaImageView) Utils.castView(view2, R.attr.ivPwdShow1, "field 'ivPwdShow1'", MryAlphaImageView.class);
            this.view7f0901f4 = view2;
            view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity.StepThree_ViewBinding.2
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            target.etPwd2Parent = Utils.findRequiredView(source, R.attr.etPwd2Parent, "field 'etPwd2Parent'");
            target.etPwd2 = (MryEditText) Utils.findRequiredViewAsType(source, R.attr.etPwd2, "field 'etPwd2'", MryEditText.class);
            View view3 = Utils.findRequiredView(source, R.attr.ivClear2, "field 'ivClear2' and method 'onClick'");
            target.ivClear2 = (MryAlphaImageView) Utils.castView(view3, R.attr.ivClear2, "field 'ivClear2'", MryAlphaImageView.class);
            this.view7f0901d1 = view3;
            view3.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity.StepThree_ViewBinding.3
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            View view4 = Utils.findRequiredView(source, R.attr.ivPwdShow2, "field 'ivPwdShow2' and method 'onClick'");
            target.ivPwdShow2 = (MryAlphaImageView) Utils.castView(view4, R.attr.ivPwdShow2, "field 'ivPwdShow2'", MryAlphaImageView.class);
            this.view7f0901f5 = view4;
            view4.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity.StepThree_ViewBinding.4
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            target.etPwd3Parent = Utils.findRequiredView(source, R.attr.etPwd3Parent, "field 'etPwd3Parent'");
            target.etPwd3 = (MryEditText) Utils.findRequiredViewAsType(source, R.attr.etPwd3, "field 'etPwd3'", MryEditText.class);
            View view5 = Utils.findRequiredView(source, R.attr.ivClear3, "field 'ivClear3' and method 'onClick'");
            target.ivClear3 = (MryAlphaImageView) Utils.castView(view5, R.attr.ivClear3, "field 'ivClear3'", MryAlphaImageView.class);
            this.view7f0901d2 = view5;
            view5.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity.StepThree_ViewBinding.5
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            View view6 = Utils.findRequiredView(source, R.attr.ivPwdShow3, "field 'ivPwdShow3' and method 'onClick'");
            target.ivPwdShow3 = (MryAlphaImageView) Utils.castView(view6, R.attr.ivPwdShow3, "field 'ivPwdShow3'", MryAlphaImageView.class);
            this.view7f0901f6 = view6;
            view6.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity.StepThree_ViewBinding.6
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            View view7 = Utils.findRequiredView(source, R.attr.btn, "method 'onClick'");
            this.view7f090097 = view7;
            view7.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity.StepThree_ViewBinding.7
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView_ViewBinding, butterknife.Unbinder
        public void unbind() {
            StepThree target = this.target;
            if (target == null) {
                throw new IllegalStateException("Bindings already cleared.");
            }
            this.target = null;
            target.etPwd1Parent = null;
            target.etPwd1 = null;
            target.ivClear1 = null;
            target.ivPwdShow1 = null;
            target.etPwd2Parent = null;
            target.etPwd2 = null;
            target.ivClear2 = null;
            target.ivPwdShow2 = null;
            target.etPwd3Parent = null;
            target.etPwd3 = null;
            target.ivClear3 = null;
            target.ivPwdShow3 = null;
            this.view7f0901d0.setOnClickListener(null);
            this.view7f0901d0 = null;
            this.view7f0901f4.setOnClickListener(null);
            this.view7f0901f4 = null;
            this.view7f0901d1.setOnClickListener(null);
            this.view7f0901d1 = null;
            this.view7f0901f5.setOnClickListener(null);
            this.view7f0901f5 = null;
            this.view7f0901d2.setOnClickListener(null);
            this.view7f0901d2 = null;
            this.view7f0901f6.setOnClickListener(null);
            this.view7f0901f6 = null;
            this.view7f090097.setOnClickListener(null);
            this.view7f090097 = null;
            super.unbind();
        }
    }

    public LoginPasswordContronllerActivity(int type) {
        this(UserConfig.selectedAccount, type, null);
    }

    public LoginPasswordContronllerActivity(int type, Bundle args) {
        this(UserConfig.selectedAccount, type, args);
    }

    public LoginPasswordContronllerActivity(int account, int type, Bundle args) {
        super(account, args);
        Bundle args2 = getArguments();
        args2 = args2 == null ? new Bundle() : args2;
        args2.putInt("contronllerType", type);
        setArguments(args2);
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        getNotificationCenter().addObserver(this, NotificationCenter.getBackupIpStatus);
        if (getArguments() != null) {
            int i = getArguments().getInt("contronllerType");
            this.contronllerType = i;
            if (i == 1 && getArguments().getString("completedPhoneNumber") == null) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("LoginPasswordContronllerActivity ===> you must transfer user's completed phone number when you want modify password or set new password.");
                    return false;
                }
                return false;
            }
        }
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        getNotificationCenter().removeObserver(this, NotificationCenter.getBackupIpStatus);
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity
    protected void initActionBar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.actionBarContainer = new FrameLayout(getParentActivity());
        this.actionBarContainer.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.rootView.addView(this.actionBarContainer, LayoutHelper.createFrame(-1, -2, 51));
        this.actionBarContainer.addView(this.actionBar, LayoutHelper.createFrame(-1, -2, 51));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                super.onItemClick(id);
                if (id == -1 && LoginPasswordContronllerActivity.this.onBackPressed()) {
                    LoginPasswordContronllerActivity.this.finishFragment();
                }
            }
        });
        TextView textView = new TextView(getParentActivity());
        this.backupIpAddressLog = textView;
        textView.setTextColor(getParentActivity().getResources().getColor(R.color.black));
        this.backupIpAddressLog.setTextSize(1, 10.0f);
        ((FrameLayout) this.fragmentView).addView(this.backupIpAddressLog, LayoutHelper.createFrame(-1, -1, 16, 160, 16, 16));
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity
    protected void initView() {
        int i = this.contronllerType;
        if (i == 0 || i == 1) {
            this.pages = new LoginContronllerBaseActivity.ThisView[3];
        } else {
            this.pages = new LoginContronllerBaseActivity.ThisView[1];
        }
        toPage(0, false, getArguments(), false);
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity
    protected void initPages(int newPageIndex) {
        if (this.pages[newPageIndex] == null) {
            this.pages[newPageIndex] = new StepThree(getParentActivity());
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity
    protected void setAcitonBar(int newPageIndex, LoginContronllerBaseActivity.ThisView thisView) {
        super.setAcitonBar(newPageIndex, thisView);
        if (this.contronllerType == 1 && this.currentViewIndex != 2) {
            this.actionBar.setTitle(thisView.getHeaderName());
        } else {
            this.actionBar.setTitle(null);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        StatusBarUtils.setStatusBarDarkTheme(getParentActivity(), true);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        TextView textView;
        if (id == NotificationCenter.getBackupIpStatus && (textView = this.backupIpAddressLog) != null) {
            textView.setText(((String) args[0]) + "（" + AndroidUtilities.getVersionName(getParentActivity()) + "）");
        }
    }

    public class StepThree extends LoginContronllerBaseActivity.ThisView {
        private boolean et1IsHide;
        private boolean et2IsHide;
        private boolean et3IsHide;

        @BindView(R.attr.etPwd1)
        MryEditText etPwd1;

        @BindView(R.attr.etPwd1Parent)
        View etPwd1Parent;

        @BindView(R.attr.etPwd2)
        MryEditText etPwd2;

        @BindView(R.attr.etPwd2Parent)
        View etPwd2Parent;

        @BindView(R.attr.etPwd3)
        MryEditText etPwd3;

        @BindView(R.attr.etPwd3Parent)
        View etPwd3Parent;
        private TextWatcher etWatcher1;
        private TextWatcher etWatcher2;
        private TextWatcher etWatcher3;

        @BindView(R.attr.ivClear1)
        MryAlphaImageView ivClear1;

        @BindView(R.attr.ivClear2)
        MryAlphaImageView ivClear2;

        @BindView(R.attr.ivClear3)
        MryAlphaImageView ivClear3;

        @BindView(R.attr.ivPwdShow1)
        MryAlphaImageView ivPwdShow1;

        @BindView(R.attr.ivPwdShow2)
        MryAlphaImageView ivPwdShow2;

        @BindView(R.attr.ivPwdShow3)
        MryAlphaImageView ivPwdShow3;

        public StepThree(Context context) {
            super(context);
            this.et1IsHide = true;
            this.et2IsHide = true;
            this.et3IsHide = true;
            this.etWatcher1 = new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity.StepThree.1
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable s) {
                    StepThree.this.changeBtnState();
                }
            };
            this.etWatcher2 = new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity.StepThree.2
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable s) {
                    StepThree.this.changeBtnState();
                }
            };
            this.etWatcher3 = new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginPasswordContronllerActivity.StepThree.3
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable s) {
                    StepThree.this.changeBtnState();
                }
            };
            View view = LayoutInflater.from(LoginPasswordContronllerActivity.this.getParentActivity()).inflate(R.layout.activity_forget_login_pwd3, (ViewGroup) null, false);
            addView(view, LayoutHelper.createLinear(-1, -1));
            initView();
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView
        protected void initView() {
            super.initView();
            this.etPwd1Parent.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(28.0f), Theme.getColor(Theme.key_windowBackgroundGray)));
            this.etPwd2Parent.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(28.0f), Theme.getColor(Theme.key_windowBackgroundGray)));
            this.etPwd3Parent.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(28.0f), Theme.getColor(Theme.key_windowBackgroundGray)));
            this.etPwd1.addTextChangedListener(this.etWatcher1);
            this.etPwd2.addTextChangedListener(this.etWatcher2);
            this.etPwd3.addTextChangedListener(this.etWatcher3);
            TLRPC.User user = MessagesController.getInstance(LoginPasswordContronllerActivity.this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(LoginPasswordContronllerActivity.this.currentAccount).getClientUserId()));
            System.out.println(String.format("user:" + user.username, new Object[0]));
            changeBtnState();
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView, im.uwrkaxlmjj.ui.components.SlideView
        public void setParams(Bundle params, boolean restore) {
            super.setParams(params, restore);
            if (params == null) {
                return;
            }
            int unused = LoginPasswordContronllerActivity.this.contronllerType;
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView
        public void onShowEnd() {
            super.onShowEnd();
            this.etPwd1.setFocusable(true);
            this.etPwd1.setFocusableInTouchMode(true);
            this.etPwd1.requestFocus();
            MryEditText mryEditText = this.etPwd1;
            mryEditText.setSelection(mryEditText.length());
            AndroidUtilities.showKeyboard(this.etPwd1);
        }

        @OnClick({R.attr.ivClear1, R.attr.ivClear2, R.attr.ivClear3, R.attr.ivPwdShow1, R.attr.ivPwdShow2, R.attr.ivPwdShow3, R.attr.btn})
        void onClick(View v) {
            int id = v.getId();
            if (id != R.attr.btn) {
                switch (id) {
                    case R.attr.ivClear1 /* 2131296720 */:
                        this.etPwd1.setText("");
                        break;
                    case R.attr.ivClear2 /* 2131296721 */:
                        this.etPwd2.setText("");
                        break;
                    case R.attr.ivClear3 /* 2131296722 */:
                        this.etPwd3.setText("");
                        break;
                    default:
                        switch (id) {
                            case R.attr.ivPwdShow1 /* 2131296756 */:
                                boolean z = !this.et1IsHide;
                                this.et1IsHide = z;
                                if (z) {
                                    this.ivPwdShow1.setImageResource(R.id.eye_close);
                                    this.etPwd1.setTransformationMethod(PasswordTransformationMethod.getInstance());
                                } else {
                                    this.ivPwdShow1.setImageResource(R.id.eye_open);
                                    this.etPwd1.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                                }
                                this.etPwd1.setSelectionEnd();
                                break;
                            case R.attr.ivPwdShow2 /* 2131296757 */:
                                boolean z2 = !this.et2IsHide;
                                this.et2IsHide = z2;
                                if (z2) {
                                    this.ivPwdShow2.setImageResource(R.id.eye_close);
                                    this.etPwd2.setTransformationMethod(PasswordTransformationMethod.getInstance());
                                } else {
                                    this.ivPwdShow2.setImageResource(R.id.eye_open);
                                    this.etPwd2.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                                }
                                this.etPwd2.setSelectionEnd();
                                break;
                            case R.attr.ivPwdShow3 /* 2131296758 */:
                                boolean z3 = !this.et3IsHide;
                                this.et3IsHide = z3;
                                if (z3) {
                                    this.ivPwdShow3.setImageResource(R.id.eye_close);
                                    this.etPwd3.setTransformationMethod(PasswordTransformationMethod.getInstance());
                                } else {
                                    this.ivPwdShow3.setImageResource(R.id.eye_open);
                                    this.etPwd3.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                                }
                                this.etPwd3.setSelectionEnd();
                                break;
                        }
                        break;
                }
            }
            checkEnterInfo(false, true, true);
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView
        protected boolean checkEnterInfo(boolean sendSmsCode, boolean showErrorToast, boolean toNextStep) {
            if (this.etPwd1.getText() == null || this.etPwd1.getText().length() == 0) {
                if (showErrorToast) {
                    ToastUtils.show(R.string.PleaseEnterYourOldPwd);
                }
                return false;
            }
            if (this.etPwd2.getText() == null || this.etPwd2.getText().length() == 0) {
                if (showErrorToast) {
                    ToastUtils.show(R.string.PleaseEnterANewPassword);
                }
                return false;
            }
            if (this.etPwd3.getText() == null || this.etPwd3.getText().length() == 0) {
                if (showErrorToast) {
                    ToastUtils.show(R.string.PaymentPasswordReEnter);
                }
                return false;
            }
            if (!LoginPasswordContronllerActivity.this.checkPasswordRule(this.etPwd1, showErrorToast) || !LoginPasswordContronllerActivity.this.checkPasswordRule(this.etPwd2, showErrorToast) || !LoginPasswordContronllerActivity.this.checkPasswordRule(this.etPwd3, showErrorToast)) {
                return false;
            }
            if (this.etPwd2.getText().toString().trim().compareTo(this.etPwd3.getText().toString().trim()) != 0) {
                if (showErrorToast) {
                    ToastUtils.show(R.string.DiffNewPayPasswordTips);
                }
                return false;
            }
            if (toNextStep) {
                resetLoginPwd();
                return true;
            }
            return true;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void changeBtnState() {
            if (this.etPwd1.length() > 0) {
                this.ivClear1.setVisibility(0);
                if (this.etPwd2.length() > 0) {
                    this.ivClear2.setVisibility(0);
                    if (this.etPwd3.length() > 0) {
                        this.ivClear3.setVisibility(0);
                        this.btn.setEnabled(true);
                        return;
                    }
                    this.ivClear3.setVisibility(8);
                } else {
                    this.ivClear2.setVisibility(8);
                }
            } else {
                this.ivClear1.setVisibility(8);
            }
            this.btn.setEnabled(false);
        }

        private void resetLoginPwd() {
            TLObject req;
            this.btn.setEnabled(false);
            int flags = 0;
            if (LoginPasswordContronllerActivity.this.contronllerType == 2) {
                req = new TLRPCLogin.TL_auth_LoginPasswordSet();
                ((TLRPCLogin.TL_auth_LoginPasswordSet) req).password = Base64.encodeToString(MD5.md5(this.etPwd1.getText().toString().trim()).getBytes(), 0);
                ((TLRPCLogin.TL_auth_LoginPasswordSet) req).password = ((TLRPCLogin.TL_auth_LoginPasswordSet) req).password.replaceAll(ShellAdbUtils.COMMAND_LINE_END, "");
            } else {
                req = new TLRPCLogin.TL_auth_LoginPasswordReset_v2();
                String current_pwd = Base64.encodeToString(MD5.md5(this.etPwd1.getText().toString().trim()).getBytes(), 0);
                String current_pwd2 = current_pwd.replaceAll(ShellAdbUtils.COMMAND_LINE_END, "");
                String new_pwd = Base64.encodeToString(MD5.md5(this.etPwd2.getText().toString().trim()).getBytes(), 0);
                String new_pwd2 = new_pwd.replaceAll(ShellAdbUtils.COMMAND_LINE_END, "");
                ((TLRPCLogin.TL_auth_LoginPasswordReset_v2) req).current_pwd_hash = current_pwd2;
                ((TLRPCLogin.TL_auth_LoginPasswordReset_v2) req).new_pwd_hash = new_pwd2;
                flags = LoginPasswordContronllerActivity.this.contronllerType != 1 ? 10 : 0;
            }
            final AlertDialog progressDialog = new AlertDialog(LoginPasswordContronllerActivity.this.getParentActivity(), 3);
            progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginPasswordContronllerActivity$StepThree$0C8Qxf5QWPK-U1rhh8rmmk2vCZE
                @Override // android.content.DialogInterface.OnCancelListener
                public final void onCancel(DialogInterface dialogInterface) {
                    this.f$0.lambda$resetLoginPwd$0$LoginPasswordContronllerActivity$StepThree(dialogInterface);
                }
            });
            LoginPasswordContronllerActivity.this.showDialog(progressDialog);
            ConnectionsManager.getInstance(LoginPasswordContronllerActivity.this.currentAccount).bindRequestToGuid(ConnectionsManager.getInstance(LoginPasswordContronllerActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginPasswordContronllerActivity$StepThree$cKz4C0Gvr1ziRbdkt481La3R70o
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$resetLoginPwd$2$LoginPasswordContronllerActivity$StepThree(progressDialog, tLObject, tL_error);
                }
            }, flags), LoginPasswordContronllerActivity.this.classGuid);
        }

        public /* synthetic */ void lambda$resetLoginPwd$0$LoginPasswordContronllerActivity$StepThree(DialogInterface dialog) {
            LoginPasswordContronllerActivity.this.getConnectionsManager().cancelRequestsForGuid(LoginPasswordContronllerActivity.this.classGuid);
            this.btn.setEnabled(true);
        }

        public /* synthetic */ void lambda$resetLoginPwd$2$LoginPasswordContronllerActivity$StepThree(final AlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginPasswordContronllerActivity$StepThree$Vz5UF73o5FMPFtEX8PlUictcVPg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$1$LoginPasswordContronllerActivity$StepThree(progressDialog, error, response);
                }
            });
        }

        public /* synthetic */ void lambda$null$1$LoginPasswordContronllerActivity$StepThree(AlertDialog progressDialog, TLRPC.TL_error error, TLObject response) {
            if (progressDialog != null) {
                progressDialog.dismiss();
            }
            this.btn.setEnabled(true);
            if (error != null) {
                LoginPasswordContronllerActivity.this.parseError(error, this.params.getString("completedPhoneNumber"));
                return;
            }
            if (response instanceof TLRPC.Bool) {
                if (response instanceof TLRPC.TL_boolTrue) {
                    if (LoginPasswordContronllerActivity.this.contronllerType != 2) {
                        if (LoginPasswordContronllerActivity.this.contronllerType == 0) {
                            ToastUtils.show(R.string.PwdResetSuccessful);
                            LoginPasswordContronllerActivity.this.finishFragment();
                            return;
                        } else {
                            LoginPasswordContronllerActivity.this.finishFragment();
                            return;
                        }
                    }
                    ToastUtils.show(R.string.TheLoginPasswordIsSetSuccessfully);
                    if (LoginPasswordContronllerActivity.this.newAccount) {
                        LoginPasswordContronllerActivity.this.newAccount = false;
                        ((LaunchActivity) LoginPasswordContronllerActivity.this.getParentActivity()).switchToAccount(LoginPasswordContronllerActivity.this.currentAccount, true);
                        LoginPasswordContronllerActivity.this.finishFragment();
                        return;
                    } else if (!LoginPasswordContronllerActivity.this.canBack) {
                        LoginPasswordContronllerActivity.this.presentFragment(new IndexActivity(), true);
                        NotificationCenter.getInstance(LoginPasswordContronllerActivity.this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
                        return;
                    } else {
                        LoginPasswordContronllerActivity.this.finishFragment();
                        NotificationCenter.getInstance(LoginPasswordContronllerActivity.this.currentAccount).postNotificationName(NotificationCenter.loginPasswordSetSuccess, new Object[0]);
                        return;
                    }
                }
                if (LoginPasswordContronllerActivity.this.contronllerType != 2) {
                    if (LoginPasswordContronllerActivity.this.contronllerType == 0) {
                        ToastUtils.show(R.string.PwdResetFailed);
                        return;
                    }
                    return;
                }
                ToastUtils.show(R.string.TheLoginPasswordIsSetFailed);
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView, im.uwrkaxlmjj.ui.components.SlideView
        public void saveStateParams(Bundle bundle) {
            super.saveStateParams(bundle);
            String pwd1 = ((Object) this.etPwd1.getText()) + "";
            String pwd2 = ((Object) this.etPwd2.getText()) + "";
            if (!TextUtils.isEmpty(pwd1)) {
                bundle.putString("pwd1", pwd1);
            }
            if (!TextUtils.isEmpty(pwd2)) {
                bundle.putString("pwd2", pwd2);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void restoreStateParams(Bundle bundle) {
            MryEditText mryEditText;
            MryEditText mryEditText2;
            super.restoreStateParams(bundle);
            String pwd1 = bundle.getString("pwd1");
            String pwd2 = bundle.getString("pwd2");
            if (!TextUtils.isEmpty(pwd1) && (mryEditText2 = this.etPwd1) != null) {
                mryEditText2.setText(pwd1);
            }
            if (!TextUtils.isEmpty(pwd2) && (mryEditText = this.etPwd2) != null) {
                mryEditText.setText(pwd1);
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView, im.uwrkaxlmjj.ui.components.SlideView
        public void onDestroyActivity() {
            TextWatcher textWatcher;
            TextWatcher textWatcher2;
            TextWatcher textWatcher3;
            MryEditText mryEditText = this.etPwd1;
            if (mryEditText != null && (textWatcher3 = this.etWatcher1) != null) {
                mryEditText.removeTextChangedListener(textWatcher3);
                this.etWatcher1 = null;
            }
            MryEditText mryEditText2 = this.etPwd2;
            if (mryEditText2 != null && (textWatcher2 = this.etWatcher2) != null) {
                mryEditText2.removeTextChangedListener(textWatcher2);
                this.etWatcher2 = null;
            }
            MryEditText mryEditText3 = this.etPwd3;
            if (mryEditText3 != null && (textWatcher = this.etWatcher3) != null) {
                mryEditText3.removeTextChangedListener(textWatcher);
                this.etWatcher3 = null;
            }
            super.onDestroyActivity();
        }
    }
}
