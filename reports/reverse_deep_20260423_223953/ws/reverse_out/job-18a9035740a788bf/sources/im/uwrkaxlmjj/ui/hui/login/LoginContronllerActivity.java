package im.uwrkaxlmjj.ui.hui.login;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.media.MediaPlayer;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.VideoView;
import androidx.constraintlayout.utils.widget.ImageFilterView;
import butterknife.BindView;
import butterknife.OnClick;
import butterknife.internal.DebouncingOnClickListener;
import butterknife.internal.Utils;
import com.alibaba.fastjson.JSONObject;
import com.blankj.utilcode.util.ScreenUtils;
import com.snail.antifake.deviceid.AndroidDeviceIMEIUtil;
import com.snail.antifake.deviceid.ShellAdbUtils;
import com.zhy.http.okhttp.OkHttpUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.RegexUtils;
import im.uwrkaxlmjj.messenger.utils.status.StatusBarUtils;
import im.uwrkaxlmjj.network.NetWorkManager;
import im.uwrkaxlmjj.network.OSSChat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCLogin;
import im.uwrkaxlmjj.translate.MD5;
import im.uwrkaxlmjj.ui.ExternalActionActivity;
import im.uwrkaxlmjj.ui.IndexActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.TwoPasswordCheckDialog;
import im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity;
import im.uwrkaxlmjj.ui.hviews.MryCheckBox;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.utils.DeviceUtils;
import im.uwrkaxlmjj.utils.VerifyCodeUtils;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class LoginContronllerActivity extends LoginContronllerBaseActivity implements NotificationCenter.NotificationCenterDelegate {
    public TextView backupIpAddressLog;
    private int contronllerType;
    protected boolean mIsLoginSuccess;
    private ActionBarMenuItem rightMenuItem;
    private VideoView videoView;

    public class PasswordView_ViewBinding extends TView_ViewBinding {
        private PasswordView target;
        private View view7f090097;
        private View view7f0901d3;

        public PasswordView_ViewBinding(PasswordView target) {
            this(target, target);
        }

        public PasswordView_ViewBinding(final PasswordView target, View source) {
            super(target, source);
            this.target = target;
            target.etGoogleCodedParent = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.etGoogleCodedParent, "field 'etGoogleCodedParent'", LinearLayout.class);
            target.etGoogleCode = (EditText) Utils.findRequiredViewAsType(source, R.attr.etGoogleCode, "field 'etGoogleCode'", EditText.class);
            View view = Utils.findRequiredView(source, R.attr.ivClearGoogleCode, "field 'ivClearGoogleCode' and method 'onClick'");
            target.ivClearGoogleCode = (ImageView) Utils.castView(view, R.attr.ivClearGoogleCode, "field 'ivClearGoogleCode'", ImageView.class);
            this.view7f0901d3 = view;
            view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.PasswordView_ViewBinding.1
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            View view2 = Utils.findRequiredView(source, R.attr.btn, "method 'onClick'");
            this.view7f090097 = view2;
            view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.PasswordView_ViewBinding.2
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView_ViewBinding, im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView_ViewBinding, butterknife.Unbinder
        public void unbind() {
            PasswordView target = this.target;
            if (target == null) {
                throw new IllegalStateException("Bindings already cleared.");
            }
            this.target = null;
            target.etGoogleCodedParent = null;
            target.etGoogleCode = null;
            target.ivClearGoogleCode = null;
            this.view7f0901d3.setOnClickListener(null);
            this.view7f0901d3 = null;
            this.view7f090097.setOnClickListener(null);
            this.view7f090097 = null;
            super.unbind();
        }
    }

    public class RegisterView_ViewBinding extends TView_ViewBinding {
        private RegisterView target;
        private View view7f090097;
        private View view7f0901d5;
        private View view7f090291;

        public RegisterView_ViewBinding(RegisterView target) {
            this(target, target);
        }

        public RegisterView_ViewBinding(final RegisterView target, View source) {
            super(target, source);
            this.target = target;
            target.etInviteCodedParent = Utils.findRequiredView(source, R.attr.etInviteCodedParent, "field 'etInviteCodedParent'");
            target.etInviteCode = (EditText) Utils.findRequiredViewAsType(source, R.attr.etInviteCode, "field 'etInviteCode'", EditText.class);
            View view = Utils.findRequiredView(source, R.attr.ivClearInviteCode, "field 'ivClearInviteCode' and method 'onClick'");
            target.ivClearInviteCode = (ImageView) Utils.castView(view, R.attr.ivClearInviteCode, "field 'ivClearInviteCode'", ImageView.class);
            this.view7f0901d5 = view;
            view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.RegisterView_ViewBinding.1
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            View view2 = Utils.findRequiredView(source, R.attr.llPrivacyAgreement, "field 'llPrivacyAgreement' and method 'onClick'");
            target.llPrivacyAgreement = view2;
            this.view7f090291 = view2;
            view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.RegisterView_ViewBinding.2
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            target.cbPrivacyAgreement = (MryCheckBox) Utils.findRequiredViewAsType(source, R.attr.cbPrivacyAgreement, "field 'cbPrivacyAgreement'", MryCheckBox.class);
            target.tvPrivacyAgreement = (MryTextView) Utils.findRequiredViewAsType(source, R.attr.tvPrivacyAgreement, "field 'tvPrivacyAgreement'", MryTextView.class);
            target.ivCode = (ImageFilterView) Utils.findRequiredViewAsType(source, R.attr.ivCode, "field 'ivCode'", ImageFilterView.class);
            target.etCode = (EditText) Utils.findRequiredViewAsType(source, R.attr.etCode, "field 'etCode'", EditText.class);
            target.llImageCode = (LinearLayout) Utils.findRequiredViewAsType(source, R.attr.ll_image_code, "field 'llImageCode'", LinearLayout.class);
            View view3 = Utils.findRequiredView(source, R.attr.btn, "method 'onClick'");
            this.view7f090097 = view3;
            view3.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.RegisterView_ViewBinding.3
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView_ViewBinding, im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView_ViewBinding, butterknife.Unbinder
        public void unbind() {
            RegisterView target = this.target;
            if (target == null) {
                throw new IllegalStateException("Bindings already cleared.");
            }
            this.target = null;
            target.etInviteCodedParent = null;
            target.etInviteCode = null;
            target.ivClearInviteCode = null;
            target.llPrivacyAgreement = null;
            target.cbPrivacyAgreement = null;
            target.tvPrivacyAgreement = null;
            target.ivCode = null;
            target.etCode = null;
            target.llImageCode = null;
            this.view7f0901d5.setOnClickListener(null);
            this.view7f0901d5 = null;
            this.view7f090291.setOnClickListener(null);
            this.view7f090291 = null;
            this.view7f090097.setOnClickListener(null);
            this.view7f090097 = null;
            super.unbind();
        }
    }

    public class TView_ViewBinding extends LoginContronllerBaseActivity.ThisView_ViewBinding {
        private TView target;
        private View view7f090097;
        private View view7f0901d7;
        private View view7f0901d9;
        private View view7f0901f4;
        private View view7f090502;

        public TView_ViewBinding(TView target) {
            this(target, target);
        }

        public TView_ViewBinding(final TView target, View source) {
            super(target, source);
            this.target = target;
            target.etPhoneNumber = (EditText) Utils.findRequiredViewAsType(source, R.attr.etPhoneNumber, "field 'etPhoneNumber'", EditText.class);
            View view = Utils.findRequiredView(source, R.attr.ivClearPhoneNumber, "field 'ivClearPhoneNumber' and method 'onClick'");
            target.ivClearPhoneNumber = (ImageView) Utils.castView(view, R.attr.ivClearPhoneNumber, "field 'ivClearPhoneNumber'", ImageView.class);
            this.view7f0901d9 = view;
            view.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView_ViewBinding.1
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            target.tvPhoneNumberInvalidTips = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvPhoneNumberInvalidTips, "field 'tvPhoneNumberInvalidTips'", TextView.class);
            target.etPassword = (EditText) Utils.findRequiredViewAsType(source, R.attr.etPassword1, "field 'etPassword'", EditText.class);
            View view2 = Utils.findRequiredView(source, R.attr.ivClearPassword1, "field 'ivClearPassword1' and method 'onClick'");
            target.ivClearPassword1 = (ImageView) Utils.castView(view2, R.attr.ivClearPassword1, "field 'ivClearPassword1'", ImageView.class);
            this.view7f0901d7 = view2;
            view2.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView_ViewBinding.2
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            View view3 = Utils.findRequiredView(source, R.attr.ivPwdShow1, "field 'ivPwdShow1' and method 'onClick'");
            target.ivPwdShow1 = (ImageView) Utils.castView(view3, R.attr.ivPwdShow1, "field 'ivPwdShow1'", ImageView.class);
            this.view7f0901f4 = view3;
            view3.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView_ViewBinding.3
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            target.tvPasswordInvalidTips1 = (TextView) Utils.findRequiredViewAsType(source, R.attr.tvPasswordInvalidTips1, "field 'tvPasswordInvalidTips1'", TextView.class);
            View view4 = Utils.findRequiredView(source, R.attr.tvLogin, "field 'tvLogin' and method 'onClick'");
            target.tvLogin = (TextView) Utils.castView(view4, R.attr.tvLogin, "field 'tvLogin'", TextView.class);
            this.view7f090502 = view4;
            view4.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView_ViewBinding.4
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
            View view5 = Utils.findRequiredView(source, R.attr.btn, "method 'onClick'");
            this.view7f090097 = view5;
            view5.setOnClickListener(new DebouncingOnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView_ViewBinding.5
                @Override // butterknife.internal.DebouncingOnClickListener
                public void doClick(View p0) {
                    target.onClick(p0);
                }
            });
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView_ViewBinding, butterknife.Unbinder
        public void unbind() {
            TView target = this.target;
            if (target == null) {
                throw new IllegalStateException("Bindings already cleared.");
            }
            this.target = null;
            target.etPhoneNumber = null;
            target.ivClearPhoneNumber = null;
            target.tvPhoneNumberInvalidTips = null;
            target.etPassword = null;
            target.ivClearPassword1 = null;
            target.ivPwdShow1 = null;
            target.tvPasswordInvalidTips1 = null;
            target.tvLogin = null;
            this.view7f0901d9.setOnClickListener(null);
            this.view7f0901d9 = null;
            this.view7f0901d7.setOnClickListener(null);
            this.view7f0901d7 = null;
            this.view7f0901f4.setOnClickListener(null);
            this.view7f0901f4 = null;
            this.view7f090502.setOnClickListener(null);
            this.view7f090502 = null;
            this.view7f090097.setOnClickListener(null);
            this.view7f090097 = null;
            super.unbind();
        }
    }

    public LoginContronllerActivity() {
        this(UserConfig.selectedAccount, null);
    }

    public LoginContronllerActivity(int account) {
        this(account, null);
    }

    public LoginContronllerActivity(int account, Bundle args) {
        super(account, args);
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        boolean tag = super.onFragmentCreate();
        if (tag) {
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.appDidLogIn);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.getBackupIpStatus);
        }
        return tag;
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity
    protected void initActionBar() {
        this.rightMenuItem = null;
        this.actionBar.setAddToContainer(false);
        this.actionBar.setBackgroundColor(0);
        this.actionBar.setItemsBackgroundColor(0, false);
        this.actionBar.setItemsColor(-1, false);
        this.actionBar.setCastShadows(false);
        this.actionBarContainer = new FrameLayout(getParentActivity());
        this.actionBarContainer.setBackgroundColor(0);
        this.rootView.addView(this.actionBarContainer, LayoutHelper.createFrame(-1, -2, 51));
        this.actionBarContainer.addView(this.actionBar, LayoutHelper.createFrame(-1, -2, 51));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                super.onItemClick(id);
                if (id == -1) {
                    if (LoginContronllerActivity.this.actionBar.getBackButton() != null && LoginContronllerActivity.this.actionBar.getBackButton().getVisibility() == 0 && LoginContronllerActivity.this.onBackPressed()) {
                        LoginContronllerActivity.this.finishFragment();
                        return;
                    }
                    return;
                }
                if (id == 1) {
                    if (LoginContronllerActivity.this.currentViewIndex == 0) {
                        LoginContronllerActivity loginContronllerActivity = LoginContronllerActivity.this;
                        loginContronllerActivity.toPage(1, true, loginContronllerActivity.pages[LoginContronllerActivity.this.currentViewIndex].getParams(), false);
                    } else {
                        LoginContronllerActivity.this.onBackPressed();
                    }
                }
            }
        });
        TextView textView = new TextView(getParentActivity());
        this.backupIpAddressLog = textView;
        textView.setTextColor(getParentActivity().getResources().getColor(R.color.black));
        this.backupIpAddressLog.setTextSize(1, 10.0f);
        ((FrameLayout) this.fragmentView).addView(this.backupIpAddressLog, LayoutHelper.createFrame(-1, -1, 16, 160, 16, 16));
    }

    private void getServerUrl() {
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        showDialog(progressDialog);
        OSSChat.getInstance().sendOSSRequest(new OSSChat.OSSChatCallback() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.2
            @Override // im.uwrkaxlmjj.network.OSSChat.OSSChatCallback
            public void onSuccess(String url) {
                progressDialog.dismiss();
                Log.d("bond", "客服链接 = " + url);
                Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(url));
                intent.putExtra("create_new_tab", true);
                intent.putExtra("com.android.browser.application_id", LoginContronllerActivity.this.getParentActivity().getPackageName());
                LoginContronllerActivity.this.getParentActivity().startActivity(intent);
            }

            @Override // im.uwrkaxlmjj.network.OSSChat.OSSChatCallback
            public void onFail() {
                progressDialog.dismiss();
                ToastUtils.show((CharSequence) "获取客服链接失败");
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity
    protected void initView() {
        initVideoView();
        this.pages = new LoginContronllerBaseActivity.ThisView[2];
        toPage(0, false, getArguments(), false);
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity
    protected void initPages(int newPageIndex) {
        if (this.pages[newPageIndex] == null) {
            if (newPageIndex == 0) {
                this.pages[newPageIndex] = new RegisterView(getParentActivity());
            } else {
                this.pages[newPageIndex] = new PasswordView(getParentActivity());
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity
    protected void setAcitonBar(int newPageIndex, LoginContronllerBaseActivity.ThisView thisView) {
        super.setAcitonBar(newPageIndex, thisView);
        ActionBarMenuItem actionBarMenuItem = this.rightMenuItem;
        if (actionBarMenuItem == null) {
            ActionBarMenu menu = this.actionBar.createMenu();
            if (newPageIndex == 0) {
                this.rightMenuItem = menu.addItem(1, LocaleController.getString(R.string.LoginByPassword));
            } else {
                this.rightMenuItem = menu.addItem(1, LocaleController.getString(R.string.SignUp));
            }
            TextView tvRight = (TextView) this.rightMenuItem.getContentView();
            tvRight.setTextSize(15.0f);
            tvRight.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            return;
        }
        TextView tvRight2 = (TextView) actionBarMenuItem.getContentView();
        if (newPageIndex == 0) {
            tvRight2.setText(LocaleController.getString(R.string.LoginByPassword));
        } else {
            tvRight2.setText(LocaleController.getString(R.string.SignUp));
        }
    }

    protected void initVideoView() {
        this.videoView = new VideoView(getParentActivity()) { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.3
            @Override // android.widget.VideoView, android.view.SurfaceView, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                setMeasuredDimension(ScreenUtils.getScreenWidth(), ScreenUtils.getScreenHeight());
            }
        };
        this.rootView.addView(this.videoView, 0, LayoutHelper.createFrame(-1, -1.0f));
        this.videoView.setOnPreparedListener(new MediaPlayer.OnPreparedListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$wbKT4gvUAmEhCMcGY6VG46ItR9Q
            @Override // android.media.MediaPlayer.OnPreparedListener
            public final void onPrepared(MediaPlayer mediaPlayer) {
                this.f$0.lambda$initVideoView$0$LoginContronllerActivity(mediaPlayer);
            }
        });
        this.videoView.setOnCompletionListener(new MediaPlayer.OnCompletionListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$ct_PUFLMmbAoLYATj6vHbiF83kQ
            @Override // android.media.MediaPlayer.OnCompletionListener
            public final void onCompletion(MediaPlayer mediaPlayer) {
                this.f$0.lambda$initVideoView$1$LoginContronllerActivity(mediaPlayer);
            }
        });
        this.videoView.setOnErrorListener(new MediaPlayer.OnErrorListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$VYS7GOraSmza-c5IKEZSf9TUvhE
            @Override // android.media.MediaPlayer.OnErrorListener
            public final boolean onError(MediaPlayer mediaPlayer, int i, int i2) {
                return this.f$0.lambda$initVideoView$2$LoginContronllerActivity(mediaPlayer, i, i2);
            }
        });
        startPlayVideo();
    }

    public /* synthetic */ void lambda$initVideoView$0$LoginContronllerActivity(MediaPlayer mp) {
        if (this.videoView != null && !isFinishing()) {
            if (this.videoView.getVisibility() != 0) {
                this.videoView.setVisibility(0);
            }
            mp.setVolume(0.0f, 0.0f);
            this.videoView.start();
        }
    }

    public /* synthetic */ void lambda$initVideoView$1$LoginContronllerActivity(MediaPlayer mp) {
        stopPlayVideo();
        startPlayVideo();
    }

    public /* synthetic */ boolean lambda$initVideoView$2$LoginContronllerActivity(MediaPlayer mp, int what, int extra) {
        VideoView videoView = this.videoView;
        if (videoView != null) {
            videoView.setVisibility(8);
            return false;
        }
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        startPlayVideo();
        setNavigationBarColor(0);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void setStatusBarTheme() {
        StatusBarUtils.setStatusBarDarkTheme(getParentActivity(), false);
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        stopPlayVideo();
    }

    protected void startPlayVideo() {
        VideoView videoView = this.videoView;
        if (videoView == null || videoView.isPlaying()) {
            return;
        }
        try {
            Uri uri = Uri.parse("android.resource://" + ApplicationLoader.applicationContext.getPackageName() + "/raw/" + R.raw.login_bg_video);
            this.videoView.setVideoURI(uri);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void stopPlayVideo() {
        VideoView videoView = this.videoView;
        if (videoView == null) {
            return;
        }
        try {
            videoView.stopPlayback();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void onAuthSuccess(TLRPC.TL_auth_authorization res) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$rsWAvR_l3swF3HgGxl_Vrmvu3gg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onAuthSuccess$3$LoginContronllerActivity();
            }
        });
        this.mIsLoginSuccess = true;
        ConnectionsManager.getInstance(this.currentAccount).setUserId(res.user.id);
        UserConfig.getInstance(this.currentAccount).clearConfig();
        MessagesController.getInstance(this.currentAccount).cleanup();
        UserConfig.getInstance(this.currentAccount).syncContacts = false;
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
        clearCurrentState();
        if (getParentActivity() instanceof LaunchActivity) {
            if (!this.newAccount) {
                presentFragment(new IndexActivity(), true);
                NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
                return;
            } else {
                this.newAccount = false;
                ((LaunchActivity) getParentActivity()).switchToAccount(this.currentAccount, true);
                finishFragment();
                return;
            }
        }
        if (getParentActivity() instanceof ExternalActionActivity) {
            ((ExternalActionActivity) getParentActivity()).onFinishLogin();
        }
    }

    public /* synthetic */ void lambda$onAuthSuccess$3$LoginContronllerActivity() {
        getNotificationCenter().postNotificationName(NotificationCenter.getBackupIpStatus, "server 5");
    }

    protected void clearCurrentState() {
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("logininfo2", 0);
        SharedPreferences.Editor editor = preferences.edit();
        editor.clear();
        editor.apply();
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle args) {
        super.saveSelfArgs(args);
        args.putInt("currentIndex", this.currentViewIndex);
        args.putBundle("pageArgs", getArguments());
        Bundle bundle = new Bundle();
        if (this.pages != null) {
            for (int i = 0; i < this.pages.length; i++) {
                LoginContronllerBaseActivity.ThisView t = this.pages[i];
                if (t != null) {
                    t.saveStateParams(bundle);
                    args.putBundle("currentIndexB" + i, bundle);
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void restoreSelfArgs(Bundle args) {
        super.restoreSelfArgs(args);
        this.currentViewIndex = args.getInt("currentIndex");
        setArguments(args.getBundle("pageArgs"));
        if (this.pages != null) {
            for (int i = 0; i < this.pages.length; i++) {
                LoginContronllerBaseActivity.ThisView t = this.pages[i];
                if (t != null) {
                    Bundle bundle = args.getBundle("currentIndexB" + i);
                    t.restoreStateParams(bundle);
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        TextView textView;
        if (id == NotificationCenter.appDidLogIn) {
            removeSelfFromStack();
            return;
        }
        if (id == NotificationCenter.getBackupIpStatus && (textView = this.backupIpAddressLog) != null) {
            textView.setText(((String) args[0]) + "（" + AndroidUtilities.getVersionName(getParentActivity()) + "）");
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.appDidLogIn);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.getBackupIpStatus);
        super.onFragmentDestroy();
        stopPlayVideo();
        this.videoView = null;
        this.rightMenuItem = null;
    }

    public class PasswordView extends TView {

        @BindView(R.attr.etGoogleCode)
        EditText etGoogleCode;
        private TextWatcher etGoogleCodeWatcher;

        @BindView(R.attr.etGoogleCodedParent)
        LinearLayout etGoogleCodedParent;

        @BindView(R.attr.ivClearGoogleCode)
        ImageView ivClearGoogleCode;
        private final AlertDialog progressDialog;

        public PasswordView(Context context) {
            super(context);
            this.etGoogleCodeWatcher = new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.PasswordView.1
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable s) {
                    PasswordView.this.ivClearGoogleCode.setVisibility((s == null || s.length() <= 0) ? 8 : 0);
                    if (TextUtils.isEmpty(s.toString())) {
                        PasswordView.this.btn.setEnabled(false);
                    } else {
                        PasswordView.this.changeBtnState();
                    }
                }
            };
            this.progressDialog = new AlertDialog(LoginContronllerActivity.this.getParentActivity(), 3);
            View view = LayoutInflater.from(context).inflate(R.layout.layout_login, (ViewGroup) null, false);
            addView(view, LayoutHelper.createFrame(-1, -1.0f));
            initView();
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView, im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView
        protected void initView() {
            super.initView();
            this.etGoogleCodedParent.setVisibility(0);
            this.etGoogleCodedParent.setVisibility(8);
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView, im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView
        protected void onShowEnd() {
            super.onShowEnd();
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView
        @OnClick({R.attr.ivClearGoogleCode, R.attr.btn})
        void onClick(View v) {
            EditText editText;
            super.onClick(v);
            int id = v.getId();
            if (id == R.attr.btn) {
                signInByPassword(this.etPhoneNumber.getText().toString(), this.etPassword.getText().toString());
            } else if (id == R.attr.ivClearGoogleCode && (editText = this.etGoogleCode) != null) {
                editText.setText("");
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void signInByPassword(String account, String pwd) {
            startTimer();
            this.btn.setEnabled(false);
            final TLRPCLogin.TL_auth_SignInByPassword req = new TLRPCLogin.TL_auth_SignInByPassword();
            String uuid = DeviceUtils.getDeviceId(ApplicationLoader.applicationContext);
            req.phone_uuid = uuid + "," + DeviceUtils.getDeviceId(ApplicationLoader.applicationContext);
            req.ip = uuid;
            Log.d("bond", "uuid = " + uuid);
            req.user_name = account;
            req.password_hash = Base64.encodeToString(MD5.md5(pwd).getBytes(), 0);
            req.password_hash = req.password_hash.replaceAll(ShellAdbUtils.COMMAND_LINE_END, "");
            LoginContronllerActivity.this.showDialog(this.progressDialog);
            Log.e("debug", "req22=" + JSONObject.toJSONString(req));
            ConnectionsManager connectionsManager = ConnectionsManager.getInstance(LoginContronllerActivity.this.currentAccount);
            final int reqId = ConnectionsManager.getInstance(LoginContronllerActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$PasswordView$bRLhSAchP1tCtrBl6dNmfh3PijE
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$signInByPassword$2$LoginContronllerActivity$PasswordView(req, tLObject, tL_error);
                }
            }, 10);
            connectionsManager.bindRequestToGuid(reqId, LoginContronllerActivity.this.classGuid);
            this.progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$PasswordView$G6fAq2ZSX0NhiytKnfHDookwwOg
                @Override // android.content.DialogInterface.OnCancelListener
                public final void onCancel(DialogInterface dialogInterface) {
                    this.f$0.lambda$signInByPassword$3$LoginContronllerActivity$PasswordView(reqId, dialogInterface);
                }
            });
        }

        public /* synthetic */ void lambda$signInByPassword$2$LoginContronllerActivity$PasswordView(final TLRPCLogin.TL_auth_SignInByPassword req, final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$PasswordView$KiDiD9rxeKua6LCqYpxbSuNpFxo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$1$LoginContronllerActivity$PasswordView(error, response, req);
                }
            });
        }

        public /* synthetic */ void lambda$null$1$LoginContronllerActivity$PasswordView(TLRPC.TL_error error, TLObject response, TLRPCLogin.TL_auth_SignInByPassword req) {
            Log.e("debug", "response222=" + JSONObject.toJSONString(error));
            this.progressDialog.dismiss();
            stopReassTimer();
            if (error == null) {
                if (response instanceof TLRPC.TL_auth_authorizationSignUpRequired) {
                    this.btn.setEnabled(true);
                    return;
                } else {
                    if (response instanceof TLRPC.TL_auth_authorization) {
                        LoginContronllerActivity.this.onAuthSuccess((TLRPC.TL_auth_authorization) response);
                        return;
                    }
                    return;
                }
            }
            Log.d("bond", "error = " + JSONObject.toJSONString(error));
            this.btn.setEnabled(true);
            if (error.text.equals("SESSION_PASSWORD_NEEDED")) {
                new TwoPasswordCheckDialog(LoginContronllerActivity.this.getParentActivity(), this.etPhoneNumber.getText().toString().trim(), new TwoPasswordCheckDialog.OnPasswordCheckListener() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.PasswordView.2
                    @Override // im.uwrkaxlmjj.ui.dialogs.TwoPasswordCheckDialog.OnPasswordCheckListener
                    public void onPasswordCheck() {
                        PasswordView passwordView = PasswordView.this;
                        passwordView.signInByPassword(passwordView.etPhoneNumber.getText().toString().trim(), PasswordView.this.etPassword.getText().toString().trim());
                    }
                }).show();
            } else {
                LoginContronllerActivity.this.parseError(error, req.user_name);
            }
        }

        private /* synthetic */ void lambda$null$0() {
            signInByPassword(this.etPhoneNumber.getText().toString().trim(), this.etPassword.getText().toString().trim());
        }

        public /* synthetic */ void lambda$signInByPassword$3$LoginContronllerActivity$PasswordView(int reqId, DialogInterface dialog) {
            LoginContronllerActivity.this.getConnectionsManager().cancelRequest(reqId, false);
            this.btn.setEnabled(true);
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView, im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView
        protected boolean checkEnterInfo(boolean sendSmsCode, boolean showErrorToast, boolean toNextStep) {
            if (!super.checkEnterInfo(sendSmsCode, showErrorToast, toNextStep) || !LoginContronllerActivity.this.checkPasswordRule(this.etPassword, showErrorToast)) {
                return false;
            }
            if (toNextStep) {
                signInByPassword(this.etPhoneNumber.getText().toString().trim(), this.etPassword.getText().toString().trim());
                return true;
            }
            return true;
        }
    }

    public class RegisterView extends TView {

        @BindView(R.attr.cbPrivacyAgreement)
        MryCheckBox cbPrivacyAgreement;

        @BindView(R.attr.etCode)
        EditText etCode;

        @BindView(R.attr.etInviteCode)
        EditText etInviteCode;

        @BindView(R.attr.etInviteCodedParent)
        View etInviteCodedParent;

        @BindView(R.attr.ivClearInviteCode)
        ImageView ivClearInviteCode;

        @BindView(R.attr.ivCode)
        ImageFilterView ivCode;

        @BindView(R.attr.ll_image_code)
        LinearLayout llImageCode;

        @BindView(R.attr.llPrivacyAgreement)
        View llPrivacyAgreement;
        private int reqCheckUNToken;

        @BindView(R.attr.tvPrivacyAgreement)
        MryTextView tvPrivacyAgreement;

        public RegisterView(Context context) {
            super(context);
            View view = LayoutInflater.from(context).inflate(R.layout.layout_register, (ViewGroup) null, false);
            addView(view, LayoutHelper.createFrame(-1, -1.0f));
            initView();
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView, im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView
        protected void initView() {
            super.initView();
            this.etInviteCodedParent.setVisibility(8);
            this.llImageCode.setVisibility(8);
        }

        private void showCode() {
            Bitmap bitmap = VerifyCodeUtils.getInstance().createBitmap();
            this.ivCode.setImageBitmap(bitmap);
            if (Build.VERSION.SDK_INT >= 21) {
                this.ivCode.setRound(8.0f);
            }
            this.ivCode.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$RegisterView$fvRraymm0mPlSuuUuEiZf077p4s
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$showCode$0$LoginContronllerActivity$RegisterView(view);
                }
            });
        }

        public /* synthetic */ void lambda$showCode$0$LoginContronllerActivity$RegisterView(View view) {
            this.ivCode.setImageBitmap(VerifyCodeUtils.getInstance().createBitmap());
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView
        @OnClick({R.attr.btn, R.attr.ivClearInviteCode, R.attr.llPrivacyAgreement})
        void onClick(View v) {
            super.onClick(v);
            int id = v.getId();
            if (id == R.attr.btn) {
                gotoNext();
                return;
            }
            if (id != R.attr.ivClearInviteCode) {
                if (id == R.attr.llPrivacyAgreement) {
                    this.cbPrivacyAgreement.setChecked(!r0.isChecked());
                    return;
                }
                return;
            }
            EditText editText = this.etInviteCode;
            if (editText != null) {
                editText.setText("");
            }
        }

        private void gotoNext() {
            checkUserName();
        }

        private void checkUserName() {
            if (this.reqCheckUNToken != 0) {
                return;
            }
            if (this.btn != null) {
                this.btn.setEnabled(false);
            }
            startTimer();
            AlertDialog progressDialog = new AlertDialog(LoginContronllerActivity.this.getParentActivity(), 3);
            progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$RegisterView$tAIIuM5aBudYFqUfecs8euv5v8A
                @Override // android.content.DialogInterface.OnCancelListener
                public final void onCancel(DialogInterface dialogInterface) {
                    this.f$0.lambda$checkUserName$1$LoginContronllerActivity$RegisterView(dialogInterface);
                }
            });
            LoginContronllerActivity.this.showDialog(progressDialog);
            ConnectionsManager.getInstance(LoginContronllerActivity.this.currentAccount).cancelRequestsForGuid(LoginContronllerActivity.this.classGuid);
            String name = this.etPhoneNumber.getText().toString().trim();
            TLRPC.TL_account_checkUsername req = new TLRPC.TL_account_checkUsername();
            req.username = name;
            ConnectionsManager connectionsManager = ConnectionsManager.getInstance(LoginContronllerActivity.this.currentAccount);
            int iSendRequest = ConnectionsManager.getInstance(LoginContronllerActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$RegisterView$8h9LzjFiQ2zOmPFcqvIbUVWEDM8
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$checkUserName$3$LoginContronllerActivity$RegisterView(tLObject, tL_error);
                }
            }, 10);
            this.reqCheckUNToken = iSendRequest;
            connectionsManager.bindRequestToGuid(iSendRequest, LoginContronllerActivity.this.classGuid);
        }

        public /* synthetic */ void lambda$checkUserName$1$LoginContronllerActivity$RegisterView(DialogInterface dialog) {
            if (this.reqCheckUNToken != 0) {
                ConnectionsManager.getInstance(LoginContronllerActivity.this.currentAccount).cancelRequest(this.reqCheckUNToken, false);
                if (this.btn != null) {
                    this.btn.setEnabled(true);
                }
                this.reqCheckUNToken = 0;
            }
        }

        public /* synthetic */ void lambda$checkUserName$3$LoginContronllerActivity$RegisterView(final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$RegisterView$y3ZmdKAkXZBO2d-uM4UQXdSwlHk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$2$LoginContronllerActivity$RegisterView(error, response);
                }
            });
        }

        public /* synthetic */ void lambda$null$2$LoginContronllerActivity$RegisterView(TLRPC.TL_error error, TLObject response) {
            LoginContronllerActivity.this.dismissCurrentDialog();
            stopReassTimer();
            if (this.btn != null) {
                this.btn.setEnabled(true);
            }
            if (error == null && (response instanceof TLRPC.TL_boolTrue)) {
                String pwdHash = Base64.encodeToString(MD5.md5(this.etPassword.getText().toString().trim()).getBytes(), 0);
                String pwdHash2 = pwdHash.replaceAll(ShellAdbUtils.COMMAND_LINE_END, "");
                LoginContronllerActivity loginContronllerActivity = LoginContronllerActivity.this;
                loginContronllerActivity.presentFragment(new ChangePersonalInformationActivity(loginContronllerActivity.newAccount, LoginContronllerActivity.this.currentAccount, this.etPhoneNumber.getText().toString().trim(), pwdHash2, null));
            } else {
                LoginContronllerActivity.this.parseError(error, null);
            }
            this.reqCheckUNToken = 0;
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView, im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView, im.uwrkaxlmjj.ui.components.SlideView
        public void onDestroyActivity() {
            if (this.reqCheckUNToken != 0) {
                ConnectionsManager.getInstance(LoginContronllerActivity.this.currentAccount).cancelRequest(this.reqCheckUNToken, false);
            }
            super.onDestroyActivity();
        }
    }

    public class TView extends LoginContronllerBaseActivity.ThisView {
        private long DELAY_MILLISECONDS;

        @BindView(R.attr.etPassword1)
        EditText etPassword;

        @BindView(R.attr.etPhoneNumber)
        EditText etPhoneNumber;
        private boolean etPwdIsHide;
        private Handler handler;

        @BindView(R.attr.ivClearPassword1)
        ImageView ivClearPassword1;

        @BindView(R.attr.ivClearPhoneNumber)
        ImageView ivClearPhoneNumber;

        @BindView(R.attr.ivPwdShow1)
        ImageView ivPwdShow1;
        private Runnable timerRunnable;

        @BindView(R.attr.tvLogin)
        TextView tvLogin;

        @BindView(R.attr.tvPasswordInvalidTips1)
        TextView tvPasswordInvalidTips1;

        @BindView(R.attr.tvPhoneNumberInvalidTips)
        TextView tvPhoneNumberInvalidTips;

        public TView(Context context) {
            super(context);
            this.etPwdIsHide = true;
            this.handler = new Handler(Looper.getMainLooper());
            this.DELAY_MILLISECONDS = OkHttpUtils.DEFAULT_MILLISECONDS;
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView
        protected void initView() {
            super.initView();
            this.etPhoneNumber.setHint(String.format(LocaleController.getString(R.string.ReminderUserNameInvalid), 5, 32));
            this.etPhoneNumber.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView.1
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable s) {
                    TView.this.checkShowInputIsInvalidTips();
                    TView.this.etPhoneNumber.setSelection(TView.this.etPhoneNumber.length());
                    TView.this.changeBtnState();
                }
            });
            this.etPassword.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginContronllerActivity.TView.2
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable editable) {
                    TView.this.checkShowPSWInputIsInvalidTips();
                    TView.this.changeBtnState();
                }
            });
            changeBtnState();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void checkShowPSWInputIsInvalidTips() {
            this.ivClearPassword1.setVisibility(TextUtils.isEmpty(this.etPassword.getText()) ? 8 : 0);
            if (LoginContronllerActivity.this.checkPasswordRule(this.etPassword.getText().toString())) {
                this.tvPasswordInvalidTips1.setVisibility(8);
            } else {
                this.tvPasswordInvalidTips1.setVisibility(0);
            }
        }

        public void startTimer() {
            Runnable runnable = this.timerRunnable;
            if (runnable != null) {
                this.handler.removeCallbacks(runnable);
            }
            Runnable runnable2 = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$TView$lInJsq1an2mR-UhC_leoM4QjVjI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$startTimer$0$LoginContronllerActivity$TView();
                }
            };
            this.timerRunnable = runnable2;
            this.handler.postDelayed(runnable2, this.DELAY_MILLISECONDS);
        }

        public /* synthetic */ void lambda$startTimer$0$LoginContronllerActivity$TView() {
            NetWorkManager.getInstance().restartApplication();
            LoginContronllerActivity.this.dismissCurrentDialog();
            this.btn.setEnabled(true);
            ToastUtils.show((CharSequence) "网络请求超时，请重试");
        }

        public void stopReassTimer() {
            Runnable runnable = this.timerRunnable;
            if (runnable != null) {
                this.handler.removeCallbacks(runnable);
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView
        protected void onShowEnd() {
            super.onShowEnd();
            this.etPhoneNumber.setFocusable(true);
            this.etPhoneNumber.setFocusableInTouchMode(true);
            this.etPhoneNumber.requestFocus();
            EditText editText = this.etPhoneNumber;
            editText.setSelection(editText.length());
            AndroidUtilities.showKeyboard(this.etPhoneNumber);
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView, im.uwrkaxlmjj.ui.components.SlideView
        public void setParams(Bundle params, boolean restore) {
            String inputPhoneNumber;
            super.setParams(params, restore);
            if (params != null && (inputPhoneNumber = params.getString("inputPhoneNumber")) != null) {
                this.etPhoneNumber.setText(inputPhoneNumber);
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView, im.uwrkaxlmjj.ui.components.SlideView
        public Bundle getParams() {
            if (this.params != null && this.etPhoneNumber.getText() != null && this.etPhoneNumber.length() > 0) {
                this.params.putString("inputPhoneNumber", this.etPhoneNumber.getText().toString().trim());
            }
            return this.params;
        }

        @OnClick({R.attr.btn, R.attr.ivClearPhoneNumber, R.attr.tvLogin, R.attr.ivClearPassword1, R.attr.ivPwdShow1})
        void onClick(View v) {
            switch (v.getId()) {
                case R.attr.ivClearPassword1 /* 2131296727 */:
                    EditText editText = this.etPassword;
                    if (editText != null) {
                        editText.setText("");
                    }
                    break;
                case R.attr.ivClearPhoneNumber /* 2131296729 */:
                    EditText editText2 = this.etPhoneNumber;
                    if (editText2 != null) {
                        editText2.setText("");
                    }
                    break;
                case R.attr.ivPwdShow1 /* 2131296756 */:
                    boolean z = !this.etPwdIsHide;
                    this.etPwdIsHide = z;
                    if (z) {
                        this.ivPwdShow1.setImageResource(R.id.eye_close);
                        this.etPassword.setTransformationMethod(PasswordTransformationMethod.getInstance());
                    } else {
                        this.ivPwdShow1.setImageResource(R.id.eye_open);
                        this.etPassword.setTransformationMethod(HideReturnsTransformationMethod.getInstance());
                    }
                    EditText editText3 = this.etPassword;
                    editText3.setSelection(editText3.getText().length());
                    break;
                case R.attr.tvLogin /* 2131297538 */:
                    if (LoginContronllerActivity.this.currentViewIndex == 0) {
                        LoginContronllerActivity loginContronllerActivity = LoginContronllerActivity.this;
                        loginContronllerActivity.toPage(1, true, loginContronllerActivity.pages[LoginContronllerActivity.this.currentViewIndex].getParams(), false);
                    } else {
                        LoginContronllerActivity loginContronllerActivity2 = LoginContronllerActivity.this;
                        loginContronllerActivity2.toPage(0, true, loginContronllerActivity2.pages[LoginContronllerActivity.this.currentViewIndex].getParams(), false);
                    }
                    break;
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView
        protected boolean checkEnterInfo(boolean sendSmsCode, boolean showErrorToast, boolean toNextStep) {
            boolean emulator = AndroidDeviceIMEIUtil.isRunOnEmulator(LoginContronllerActivity.this.getParentActivity());
            if (emulator) {
                ToastUtils.show((CharSequence) LocaleController.getString(R.string.OperatingEnvironmentAbnormal));
                return false;
            }
            if (this.etPhoneNumber.getText() == null || this.etPhoneNumber.getText().length() == 0) {
                if (showErrorToast) {
                    LoginContronllerActivity.this.needShowAlert(LocaleController.getString(R.string.PleaseEnterAccountName));
                }
                return false;
            }
            String accountStr = this.etPhoneNumber.getText().toString().trim();
            if (accountStr.length() < 5 || accountStr.length() > 32 || !RegexUtils.firstLetterIsEnglishLetter(accountStr) || !LoginContronllerBaseActivity.isUserName(accountStr)) {
                if (showErrorToast) {
                    LoginContronllerActivity.this.needShowAlert(String.format(LocaleController.getString(R.string.ReminderUserNameInvalid), 5, 32));
                }
                return false;
            }
            if (LoginContronllerActivity.this.getParentActivity() instanceof LaunchActivity) {
                for (int a = 0; a < 3; a++) {
                    UserConfig userConfig = UserConfig.getInstance(a);
                    if (userConfig.isClientActivated()) {
                        String username = userConfig.getCurrentUser().username;
                        if (!TextUtils.isEmpty(username) && username.equals(accountStr)) {
                            if (showErrorToast) {
                                final int num = a;
                                AlertDialog.Builder builder = new AlertDialog.Builder(LoginContronllerActivity.this.getParentActivity());
                                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                                builder.setMessage(LocaleController.getString("AccountAlreadyLoggedIn", R.string.AccountAlreadyLoggedIn));
                                builder.setPositiveButton(LocaleController.getString("AccountSwitch", R.string.AccountSwitch), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginContronllerActivity$TView$5Lp3mwU5UESriYBIIAmT8MRIDwU
                                    @Override // android.content.DialogInterface.OnClickListener
                                    public final void onClick(DialogInterface dialogInterface, int i) {
                                        this.f$0.lambda$checkEnterInfo$1$LoginContronllerActivity$TView(num, dialogInterface, i);
                                    }
                                });
                                builder.setNegativeButton(LocaleController.getString("OK", R.string.OK), null);
                                LoginContronllerActivity.this.showDialog(builder.create());
                            }
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        public /* synthetic */ void lambda$checkEnterInfo$1$LoginContronllerActivity$TView(int num, DialogInterface dialog, int which) {
            if (UserConfig.selectedAccount != num) {
                ((LaunchActivity) LoginContronllerActivity.this.getParentActivity()).switchToAccount(num, false);
            }
            LoginContronllerActivity.this.finishFragment();
        }

        protected void checkShowInputIsInvalidTips() {
            if (this.etPhoneNumber.getText() != null && this.etPhoneNumber.getText().length() > 0) {
                this.ivClearPhoneNumber.setVisibility(0);
            } else {
                this.ivClearPhoneNumber.setVisibility(8);
            }
            this.tvPhoneNumberInvalidTips.setText(String.format(LocaleController.getString(R.string.ReminderUserNameInvalid), 5, 32));
            boolean tag = this.etPhoneNumber.getText() != null && this.etPhoneNumber.length() > 0;
            if (tag) {
                String accountStr = this.etPhoneNumber.getText().toString().trim();
                if (accountStr.length() < 5 || accountStr.length() > 32 || !RegexUtils.firstLetterIsEnglishLetter(accountStr) || !LoginContronllerBaseActivity.isUserName(accountStr)) {
                    if (this.tvPhoneNumberInvalidTips.getVisibility() != 0) {
                        this.tvPhoneNumberInvalidTips.setVisibility(0);
                        return;
                    }
                    return;
                } else {
                    if (this.tvPhoneNumberInvalidTips.getVisibility() != 8) {
                        this.tvPhoneNumberInvalidTips.setVisibility(8);
                        return;
                    }
                    return;
                }
            }
            if (this.tvPhoneNumberInvalidTips.getVisibility() != 0) {
                this.tvPhoneNumberInvalidTips.setVisibility(0);
            }
        }

        protected void changeBtnState() {
            this.btn.setEnabled(LoginContronllerActivity.this.checkUserNameRule(this.etPhoneNumber.getText().toString()) && LoginContronllerActivity.this.checkPasswordRule(this.etPassword.getText().toString()));
        }

        @Override // im.uwrkaxlmjj.ui.hui.login.LoginContronllerBaseActivity.ThisView, im.uwrkaxlmjj.ui.components.SlideView
        public void onDestroyActivity() {
            if (LoginContronllerActivity.this.mKeyboardChangeListener != null) {
                LoginContronllerActivity.this.mKeyboardChangeListener.destroy();
                LoginContronllerActivity.this.mKeyboardChangeListener = null;
            }
            stopReassTimer();
            super.onDestroyActivity();
        }
    }
}
