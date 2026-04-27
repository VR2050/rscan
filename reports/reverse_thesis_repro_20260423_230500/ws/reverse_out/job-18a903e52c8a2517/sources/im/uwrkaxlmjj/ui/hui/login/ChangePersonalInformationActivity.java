package im.uwrkaxlmjj.ui.hui.login;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputFilter;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Log;
import android.util.Property;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.ImageView;
import android.widget.TextView;
import butterknife.BindView;
import butterknife.OnClick;
import com.alibaba.fastjson.JSONObject;
import com.bigkoo.pickerview.listener.OnOptionsSelectListener;
import com.bigkoo.pickerview.listener.OnTimeSelectListener;
import com.blankj.utilcode.util.TimeUtils;
import com.king.zxing.util.CodeUtils;
import com.snail.antifake.deviceid.AndroidDeviceIMEIUtil;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCLogin;
import im.uwrkaxlmjj.ui.ExternalActionActivity;
import im.uwrkaxlmjj.ui.IndexActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ImageUpdater;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.filter.MaxByteLengthFilter;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.OptionsWheelPickerDialog;
import im.uwrkaxlmjj.ui.dialogs.TimeWheelPickerDialog;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryRoundButtonDrawable;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.utils.DeviceUtils;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChangePersonalInformationActivity extends BaseFragment implements ImageUpdater.ImageUpdaterDelegate, NotificationCenter.NotificationCenterDelegate {
    private String accoutName;
    private TLRPC.FileLocation avatar;
    private AnimatorSet avatarAnimation;
    private TLRPC.FileLocation avatarBig;
    private AvatarDrawable avatarDrawable;

    @BindView(R.attr.btnDone)
    MryRoundButton btnDone;
    private String city;

    @BindView(R.attr.containerAvatar)
    View containerAvatar;

    @BindView(R.attr.containerCamera)
    View containerCamera;

    @BindView(R.attr.containerFemale)
    View containerFemale;

    @BindView(R.attr.containerGenderSelect)
    View containerGenderSelect;

    @BindView(R.attr.containerMale)
    View containerMale;
    private String country;
    private int currentAccount;
    private TextWatcher etNameWatcher;

    @BindView(R.attr.etNickName)
    MryEditText etNickName;
    private String inviteCode;
    private String ip;
    private boolean isRegisterUser;

    @BindView(R.attr.ivAvatar)
    BackupImageView ivAvatar;

    @BindView(R.attr.ivAvatarProgress)
    RadialProgressView ivAvatarProgress;

    @BindView(R.attr.ivCamera)
    ImageView ivCamera;

    @BindView(R.attr.ivFemale)
    ImageView ivFemale;

    @BindView(R.attr.ivMale)
    ImageView ivMale;

    @BindView(R.attr.ivMore)
    ImageView ivMore;
    private TLRPC.InputFile mAvatarFile;
    private int mBirth;
    private boolean mCanGoBack;
    private String mCurrentSelectPhotoPath;
    private MryRoundButtonDrawable mDrawableFemale;
    private MryRoundButtonDrawable mDrawableMale;
    private int mGender;
    private OptionsWheelPickerDialog.Builder<String> mGenderPickerBulder;
    private ImageUpdater mImageUpdater;
    private boolean mIsLoginSuccess;
    private boolean mShouldShowGenderDialog;
    private TimeWheelPickerDialog.Builder mTimePickerBuilder;
    private TLRPC.User mUser;
    private boolean newAccount;
    private String pwdHash;

    @BindView(R.attr.selectDataOfBirthParent)
    View selectDataOfBirthParent;

    @BindView(R.attr.selectSexParent)
    View selectSexParent;

    @BindView(R.attr.tvCamera)
    MryTextView tvCamera;

    @BindView(R.attr.tvDate)
    TextView tvDate;

    @BindView(R.attr.tvFemale)
    MryTextView tvFemale;

    @BindView(R.attr.tvMale)
    MryTextView tvMale;

    @BindView(R.attr.tvSelectDateOfBirth)
    MryTextView tvSelectDateOfBirth;

    @BindView(R.attr.tvSelectSex)
    MryTextView tvSelectSex;

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public /* synthetic */ String getInitialSearchString() {
        return ImageUpdater.ImageUpdaterDelegate.CC.$default$getInitialSearchString(this);
    }

    public ChangePersonalInformationActivity(int currentAccount) {
        this.mShouldShowGenderDialog = true;
        this.etNameWatcher = new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity.5
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                ChangePersonalInformationActivity.this.changeBtnEnbale();
            }
        };
        this.currentAccount = currentAccount;
        this.mCanGoBack = false;
        this.isRegisterUser = false;
    }

    public ChangePersonalInformationActivity(boolean newAccount, int currentAccount, String accoutName, String pwdHash, String inviteCode) {
        this.mShouldShowGenderDialog = true;
        this.etNameWatcher = new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity.5
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                ChangePersonalInformationActivity.this.changeBtnEnbale();
            }
        };
        this.newAccount = newAccount;
        this.currentAccount = currentAccount;
        this.accoutName = accoutName;
        this.pwdHash = pwdHash;
        this.inviteCode = inviteCode;
        this.isRegisterUser = true;
        this.mCanGoBack = true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.FileDidUpload);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.FileDidFailUpload);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        TextWatcher textWatcher;
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileDidUpload);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileDidFailUpload);
        BackupImageView backupImageView = this.ivAvatar;
        if (backupImageView != null) {
            backupImageView.setImageDrawable(null);
        }
        this.mDrawableMale = null;
        this.mDrawableFemale = null;
        this.avatarDrawable = null;
        ImageUpdater imageUpdater = this.mImageUpdater;
        if (imageUpdater != null) {
            imageUpdater.clear();
            this.mImageUpdater = null;
        }
        this.mAvatarFile = null;
        this.avatar = null;
        this.avatarBig = null;
        this.mTimePickerBuilder = null;
        AnimatorSet animatorSet = this.avatarAnimation;
        if (animatorSet != null && (animatorSet.isRunning() || this.avatarAnimation.isStarted())) {
            this.avatarAnimation.cancel();
        }
        this.avatarAnimation = null;
        MryEditText mryEditText = this.etNickName;
        if (mryEditText != null && (textWatcher = this.etNameWatcher) != null) {
            mryEditText.removeTextChangedListener(textWatcher);
            this.etNameWatcher = null;
        }
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_change_personal_information, (ViewGroup) null);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.actionBar.setTitle(LocaleController.getString(R.string.SignUp));
        useButterKnife();
        initActionBar();
        initView();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        if (this.mCanGoBack) {
            this.actionBar.setBackButtonImage(R.id.ic_back);
            this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity.1
                @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
                public void onItemClick(int id) {
                    super.onItemClick(id);
                    if (id == -1 && !ChangePersonalInformationActivity.this.back()) {
                        ChangePersonalInformationActivity.this.finishFragment();
                    }
                }
            });
        }
    }

    private void initView() {
        this.tvCamera.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText7));
        MryRoundButtonDrawable containerAvatarBg = new MryRoundButtonDrawable();
        containerAvatarBg.setIsRadiusAdjustBounds(false);
        containerAvatarBg.setCornerRadius(AndroidUtilities.dp(90.0f));
        containerAvatarBg.setStrokeData(AndroidUtilities.dp(2.0f), ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhiteGrayLine)));
        containerAvatarBg.setBgData(ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundGray)));
        this.ivMore.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteGrayLine), PorterDuff.Mode.SRC_IN));
        this.btnDone.setPrimaryRadiusAdjustBoundsFillStyle();
        this.containerAvatar.setBackground(containerAvatarBg);
        this.ivAvatar.setRoundRadius(AndroidUtilities.dp(90.0f));
        ImageUpdater imageUpdater = new ImageUpdater();
        this.mImageUpdater = imageUpdater;
        imageUpdater.setSearchAvailable(false);
        this.mImageUpdater.setUploadAfterSelect(false);
        this.mImageUpdater.parentFragment = this;
        this.mImageUpdater.delegate = this;
        this.ivAvatarProgress.setSize(AndroidUtilities.dp(30.0f));
        this.ivAvatarProgress.setProgressColor(Theme.getColor(Theme.key_progressCircle));
        this.etNickName.setFilters(new InputFilter[]{new MaxByteLengthFilter(), new InputFilter() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$AXzGEVzMZB8p3U9jexpkwXxeZwA
            @Override // android.text.InputFilter
            public final CharSequence filter(CharSequence charSequence, int i, int i2, Spanned spanned, int i3, int i4) {
                return ChangePersonalInformationActivity.lambda$initView$0(charSequence, i, i2, spanned, i3, i4);
            }
        }});
        this.etNickName.addTextChangedListener(this.etNameWatcher);
        this.avatarDrawable = new AvatarDrawable();
        loadCurrentState();
        if (!this.isRegisterUser) {
            TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()));
            this.mUser = user;
            this.ivAvatar.setImage(ImageLocation.getForUser(user, false), "100_100", this.avatarDrawable, this.mUser);
            if (!TextUtils.isEmpty(this.mUser.first_name)) {
                this.etNickName.setText(this.mUser.first_name);
            }
        } else {
            String str = this.mCurrentSelectPhotoPath;
            if (str != null) {
                this.ivAvatar.setImage(str, "100_100", this.avatarDrawable);
            }
        }
        changeGender();
        this.containerAvatar.setVisibility(8);
        this.selectSexParent.setVisibility(8);
        this.etNickName.setVisibility(0);
        this.selectDataOfBirthParent.setVisibility(8);
    }

    static /* synthetic */ CharSequence lambda$initView$0(CharSequence source, int start, int end, Spanned dest, int dstart, int dend) {
        if (dstart == 0 && source != null && source.toString().contains(" ")) {
            return "";
        }
        return null;
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

    @OnClick({R.attr.containerAvatar, R.attr.containerMale, R.attr.containerFemale, R.attr.tvDate, R.attr.btnDone, R.attr.selectSexParent})
    void onClick(View v) {
        switch (v.getId()) {
            case R.attr.btnDone /* 2131296412 */:
                check();
                break;
            case R.attr.containerAvatar /* 2131296480 */:
                TLRPC.User user = this.mUser;
                if (user != null) {
                    ImageUpdater imageUpdater = this.mImageUpdater;
                    if (user.photo != null && this.mUser.photo.photo_big != null && !(this.mUser.photo instanceof TLRPC.TL_userProfilePhotoEmpty)) {
                        z = true;
                    }
                    imageUpdater.openMenu(z, new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$DP6LQ7s7sUdoQZlXr7gqHMm-m_M
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onClick$1$ChangePersonalInformationActivity();
                        }
                    });
                } else {
                    this.mImageUpdater.openMenu(this.avatar != null, new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$kAJBjAlHNqu5BQWwOogqow8xxUI
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.resetAvatar();
                        }
                    });
                }
                break;
            case R.attr.containerFemale /* 2131296485 */:
                this.mGender = 2;
                changeGender();
                if (this.mShouldShowGenderDialog) {
                    this.mShouldShowGenderDialog = false;
                    needShowAlert(LocaleController.getString(R.string.CannotBeModifiedAfterGenderDetermination), true, null);
                }
                break;
            case R.attr.containerMale /* 2131296489 */:
                this.mGender = 1;
                changeGender();
                if (this.mShouldShowGenderDialog) {
                    this.mShouldShowGenderDialog = false;
                    needShowAlert(LocaleController.getString(R.string.CannotBeModifiedAfterGenderDetermination), true, null);
                }
                break;
            case R.attr.selectSexParent /* 2131297276 */:
                showSexSelectDialog();
                break;
            case R.attr.tvDate /* 2131297475 */:
                showSelectBirthDialog();
                break;
        }
    }

    public /* synthetic */ void lambda$onClick$1$ChangePersonalInformationActivity() {
        MessagesController.getInstance(this.currentAccount).deleteUserPhoto(null);
        resetAvatar();
    }

    private void check() {
        if (this.isRegisterUser) {
            if (this.accoutName == null) {
                ToastUtils.show(R.string.PleaseEnterAccountName);
                finishFragment();
                return;
            } else if (this.pwdHash == null) {
                ToastUtils.show(R.string.PaymentPasswordEnter);
                finishFragment();
                return;
            }
        }
        if (TextUtils.isEmpty(((Object) this.etNickName.getText()) + "") || this.etNickName.getText().toString().trim().replaceAll(" ", "").length() == 0) {
            ToastUtils.show(R.string.PleaseFillInNickName);
        } else if (this.isRegisterUser) {
            signUp(this.ip, this.country, this.city);
        } else {
            setUserInformation();
        }
    }

    private void setUserInformation() {
        TLRPCLogin.TL_account_setUserDetail req = new TLRPCLogin.TL_account_setUserDetail();
        req.photo = this.mAvatarFile;
        req.first_name = clearEndOfStrSpace(this.etNickName.getText().toString().trim());
        req.sex = this.mGender;
        req.birthday = this.mBirth;
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        showDialog(progressDialog);
        ConnectionsManager connectionsManager = ConnectionsManager.getInstance(this.currentAccount);
        final int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$4XBl17Qfsy4gh9O3ecf27EGZBb4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$setUserInformation$3$ChangePersonalInformationActivity(progressDialog, tLObject, tL_error);
            }
        });
        connectionsManager.bindRequestToGuid(reqId, this.classGuid);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$6cCLj651UWNSs65dC3yzyw0ooII
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$setUserInformation$4$ChangePersonalInformationActivity(reqId, dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$setUserInformation$3$ChangePersonalInformationActivity(final AlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$bImdhTA_wmVxRmU9WB-rlLqhn9I
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$ChangePersonalInformationActivity(error, response, progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$ChangePersonalInformationActivity(TLRPC.TL_error error, TLObject response, AlertDialog progressDialog) {
        if (error == null && (response instanceof TLRPC.UserFull)) {
            updateUserData((TLRPC.UserFull) response, progressDialog);
        } else {
            progressDialog.dismiss();
            parseError(error);
        }
    }

    public /* synthetic */ void lambda$setUserInformation$4$ChangePersonalInformationActivity(int reqId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, false);
    }

    private void signUp(String ip, String country, String city) {
        boolean emulator = AndroidDeviceIMEIUtil.isRunOnEmulator(getParentActivity());
        if (emulator) {
            ToastUtils.show((CharSequence) LocaleController.getString(R.string.OperatingEnvironmentAbnormal));
            return;
        }
        this.btnDone.setEnabled(false);
        TLRPCLogin.TL_auth_SignUpV1 req = new TLRPCLogin.TL_auth_SignUpV1();
        TLRPC.TL_dataJSON extend = new TLRPC.TL_dataJSON();
        req.extend = extend;
        String uuid = DeviceUtils.getDeviceId(getParentActivity());
        req.phone_uuid = uuid;
        TLRPC.TL_inputFile photo = new TLRPC.TL_inputFile();
        photo.id = 0L;
        photo.parts = 0;
        photo.name = "";
        photo.md5_checksum = "";
        req.photo = photo;
        try {
            req.first_name = clearEndOfStrSpace(this.etNickName.getText().toString().trim());
        } catch (Exception e) {
            FileLog.e(getClass().getName(), "sn fn error: ", e);
        }
        req.sex = 0;
        req.birthday = 0;
        req.user_name = this.accoutName;
        req.password_hash = this.pwdHash;
        JSONObject extendJson = new JSONObject();
        if (!TextUtils.isEmpty(this.inviteCode)) {
            extendJson.put("ProxyCode", (Object) this.inviteCode);
        }
        if (!TextUtils.isEmpty(ip)) {
            extendJson.put("ip", (Object) ip);
        }
        if (!TextUtils.isEmpty(country)) {
            extendJson.put("country", (Object) country);
        }
        if (!TextUtils.isEmpty(city)) {
            extendJson.put("city", (Object) city);
        }
        extendJson.put("macAddress", (Object) DeviceUtils.getDeviceId(getParentActivity()));
        extendJson.put("devUuid", (Object) DeviceUtils.getDeviceId(getParentActivity()));
        FileLog.d(ChangePersonalInformationActivity.class.getSimpleName(), "extj = " + extendJson.toJSONString());
        req.extend = new TLRPC.TL_dataJSON();
        req.extend.data = extendJson.toJSONString();
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        showDialog(progressDialog);
        final long time = System.currentTimeMillis();
        Log.e("debug", "start==" + JSONObject.toJSONString(req));
        ConnectionsManager connectionsManager = ConnectionsManager.getInstance(this.currentAccount);
        final int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$Fvq-vr9EJLmsk7Ue7WCXdYAjCOI
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$signUp$6$ChangePersonalInformationActivity(progressDialog, time, tLObject, tL_error);
            }
        }, 10);
        connectionsManager.bindRequestToGuid(reqId, this.classGuid);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$DxWPnIGVJHrtYUmrovXoC_ap8JU
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$signUp$7$ChangePersonalInformationActivity(reqId, dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$signUp$6$ChangePersonalInformationActivity(final AlertDialog progressDialog, final long time, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$QYahTTbaoPh8RrRAFzcri1OHZzk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$ChangePersonalInformationActivity(progressDialog, time, error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$ChangePersonalInformationActivity(AlertDialog progressDialog, long time, TLRPC.TL_error error, TLObject response) {
        progressDialog.dismiss();
        Log.e("debug", "end==" + (System.currentTimeMillis() - time));
        Log.e("debug", "error==" + error);
        if (error == null && (response instanceof TLRPC.TL_auth_authorization)) {
            onAuthSuccess((TLRPC.TL_auth_authorization) response);
        } else {
            parseError(error);
            this.btnDone.setEnabled(true);
        }
    }

    public /* synthetic */ void lambda$signUp$7$ChangePersonalInformationActivity(int reqId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, false);
        this.btnDone.setEnabled(true);
    }

    private void changeGender() {
        if (this.mDrawableMale == null) {
            this.mDrawableMale = new MryRoundButtonDrawable();
        }
        if (this.mDrawableFemale == null) {
            this.mDrawableFemale = new MryRoundButtonDrawable();
        }
        int i = this.mGender;
        if (i == 1) {
            this.mDrawableMale.setStrokeData(1, ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton)));
            this.mDrawableMale.setIsRadiusAdjustBounds(true);
            this.mDrawableMale.setBgData(ColorStateList.valueOf(Theme.getColor(Theme.key_actionBarTabUnactiveText)));
            this.containerMale.setBackground(this.mDrawableMale);
            this.ivMale.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton), PorterDuff.Mode.SRC_IN));
            this.tvMale.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
            this.mDrawableFemale.setStrokeData(1, ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhiteGrayLine)));
            this.mDrawableFemale.setIsRadiusAdjustBounds(true);
            this.mDrawableFemale.setBgData(ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhite)));
            this.containerFemale.setBackground(this.mDrawableFemale);
            this.ivFemale.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6), PorterDuff.Mode.SRC_IN));
            this.tvFemale.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
        } else if (i == 2) {
            this.mDrawableMale.setStrokeData(1, ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhiteGrayLine)));
            this.mDrawableMale.setIsRadiusAdjustBounds(true);
            this.mDrawableMale.setBgData(ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhite)));
            this.containerMale.setBackground(this.mDrawableMale);
            this.ivMale.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6), PorterDuff.Mode.SRC_IN));
            this.tvMale.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.mDrawableFemale.setStrokeData(1, ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton)));
            this.mDrawableFemale.setIsRadiusAdjustBounds(true);
            this.mDrawableFemale.setBgData(ColorStateList.valueOf(Theme.getColor(Theme.key_actionBarTabUnactiveText)));
            this.containerFemale.setBackground(this.mDrawableFemale);
            this.ivFemale.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton), PorterDuff.Mode.SRC_IN));
            this.tvFemale.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
        } else {
            this.mDrawableMale.setStrokeData(1, ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhiteGrayLine)));
            this.mDrawableMale.setIsRadiusAdjustBounds(true);
            this.mDrawableMale.setBgData(ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhite)));
            this.containerMale.setBackground(this.mDrawableMale);
            this.ivMale.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6), PorterDuff.Mode.SRC_IN));
            this.tvMale.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.mDrawableFemale.setStrokeData(1, ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhiteGrayLine)));
            this.mDrawableFemale.setIsRadiusAdjustBounds(true);
            this.mDrawableFemale.setBgData(ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhite)));
            this.containerFemale.setBackground(this.mDrawableFemale);
            this.ivFemale.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6), PorterDuff.Mode.SRC_IN));
            this.tvFemale.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
        }
        changeBtnEnbale();
    }

    private void startUploadAvatarPhoto() {
        if (this.avatarBig != null) {
            MessagesController.getInstance(this.currentAccount).uploadAvatar(this.avatarBig);
            showAvatarProgress(true, true);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> photos, boolean notify, int scheduleDate) {
        if (photos != null) {
            this.mCurrentSelectPhotoPath = photos.get(0).path;
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.ImageUpdater.ImageUpdaterDelegate
    public void didUploadPhoto(final TLRPC.InputFile file, final TLRPC.PhotoSize bigSize, final TLRPC.PhotoSize smallSize) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$_qysJo1NJBqr7wfzYATmMwkGi50
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$didUploadPhoto$10$ChangePersonalInformationActivity(file, smallSize, bigSize);
            }
        });
    }

    public /* synthetic */ void lambda$didUploadPhoto$10$ChangePersonalInformationActivity(TLRPC.InputFile file, TLRPC.PhotoSize smallSize, TLRPC.PhotoSize bigSize) {
        if (file != null) {
            TLRPC.TL_photos_uploadProfilePhoto req = new TLRPC.TL_photos_uploadProfilePhoto();
            req.file = file;
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$fFzjhMNuAIIWwIC7ACXzAM6EUkk
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$9$ChangePersonalInformationActivity(tLObject, tL_error);
                }
            });
        } else {
            this.avatar = smallSize.location;
            this.avatarBig = bigSize.location;
            this.ivAvatar.setImage(ImageLocation.getForLocal(this.avatar), "87_87", this.avatarDrawable, (Object) null);
            startUploadAvatarPhoto();
        }
    }

    public /* synthetic */ void lambda$null$9$ChangePersonalInformationActivity(TLObject response, TLRPC.TL_error error) {
        if (error == null) {
            TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()));
            if (user == null) {
                user = UserConfig.getInstance(this.currentAccount).getCurrentUser();
                if (user != null) {
                    MessagesController.getInstance(this.currentAccount).putUser(user, false);
                } else {
                    return;
                }
            } else {
                UserConfig.getInstance(this.currentAccount).setCurrentUser(user);
            }
            TLRPC.TL_photos_photo photo = (TLRPC.TL_photos_photo) response;
            ArrayList<TLRPC.PhotoSize> sizes = photo.photo.sizes;
            TLRPC.PhotoSize small = FileLoader.getClosestPhotoSizeWithSize(sizes, 150);
            TLRPC.PhotoSize big = FileLoader.getClosestPhotoSizeWithSize(sizes, CodeUtils.DEFAULT_REQ_HEIGHT);
            user.photo = new TLRPC.TL_userProfilePhoto();
            user.photo.photo_id = photo.photo.id;
            if (small != null) {
                user.photo.photo_small = small.location;
            }
            if (big != null) {
                user.photo.photo_big = big.location;
            } else if (small != null) {
                user.photo.photo_small = small.location;
            }
            if (photo != null) {
                if (small != null && this.avatar != null) {
                    File destFile = FileLoader.getPathToAttach(small, true);
                    File src = FileLoader.getPathToAttach(this.avatar, true);
                    src.renameTo(destFile);
                    String oldKey = this.avatar.volume_id + "_" + this.avatar.local_id + "@50_50";
                    String newKey = small.location.volume_id + "_" + small.location.local_id + "@50_50";
                    ImageLoader.getInstance().replaceImageInCache(oldKey, newKey, ImageLocation.getForUser(user, false), true);
                }
                if (big != null && this.avatarBig != null) {
                    File destFile2 = FileLoader.getPathToAttach(big, true);
                    File src2 = FileLoader.getPathToAttach(this.avatarBig, true);
                    src2.renameTo(destFile2);
                }
            }
            MessagesStorage.getInstance(this.currentAccount).clearUserPhotos(user.id);
            ArrayList<TLRPC.User> users = new ArrayList<>();
            users.add(user);
            MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(users, null, false, true);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$ONWzYj-OISsqoa3I2NUIHZS2lzU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$8$ChangePersonalInformationActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$8$ChangePersonalInformationActivity() {
        this.avatar = null;
        this.avatarBig = null;
        updateUserData(null, null);
        showAvatarProgress(false, true);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.updateInterfaces, Integer.valueOf(MessagesController.UPDATE_MASK_ALL));
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
        UserConfig.getInstance(this.currentAccount).saveConfig(true);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.FileDidUpload) {
            if (args != null && args.length >= 2) {
                this.mAvatarFile = (TLRPC.InputFile) args[1];
                showAvatarProgress(false, true);
                changeBtnEnbale();
                if (!this.isRegisterUser) {
                    TLRPC.User user = this.mUser;
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.FileDidFailUpload) {
            showAvatarProgress(false, false);
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString(R.string.AppName));
            builder.setMessage(LocaleController.getString(R.string.TipsFailedToUploadAvatarTryAgain));
            builder.setPositiveButton(LocaleController.getString(R.string.Retry), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$ZIYylAyepNS6CSbqxqKYuvByd6w
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$didReceivedNotification$11$ChangePersonalInformationActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString(R.string.Cancel), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$rdtFZejyK4_Q5P4ALLS-kB-ECJc
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$didReceivedNotification$12$ChangePersonalInformationActivity(dialogInterface, i);
                }
            });
            builder.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$xKRLjXWh8Lt82DeuKexeKx7A3zE
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$didReceivedNotification$13$ChangePersonalInformationActivity(dialogInterface);
                }
            });
            showDialog(builder.create());
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$11$ChangePersonalInformationActivity(DialogInterface dialog, int which) {
        startUploadAvatarPhoto();
    }

    public /* synthetic */ void lambda$didReceivedNotification$12$ChangePersonalInformationActivity(DialogInterface dialog, int which) {
        resetAvatar();
    }

    public /* synthetic */ void lambda$didReceivedNotification$13$ChangePersonalInformationActivity(DialogInterface dialog) {
        resetAvatar();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) throws FileNotFoundException {
        ImageUpdater imageUpdater = this.mImageUpdater;
        if (imageUpdater != null) {
            imageUpdater.onActivityResult(requestCode, resultCode, data);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResultFragment(requestCode, permissions, grantResults);
        if (grantResults != null && grantResults[0] == 0) {
            if (requestCode == 19) {
                this.mImageUpdater.openCamera();
            } else if (requestCode == 4) {
                this.mImageUpdater.openGallery();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resetAvatar() {
        this.mAvatarFile = null;
        this.avatar = null;
        this.avatarBig = null;
        showAvatarProgress(false, true);
        this.ivAvatar.setImage((ImageLocation) null, (String) null, this.avatarDrawable, (Object) null);
        this.containerCamera.setVisibility(0);
        changeBtnEnbale();
    }

    private void showAvatarProgress(final boolean show, boolean animated) {
        if (this.containerCamera == null) {
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
                this.ivAvatarProgress.setVisibility(0);
                this.avatarAnimation.playTogether(ObjectAnimator.ofFloat(this.containerCamera, (Property<View, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.ivAvatarProgress, (Property<RadialProgressView, Float>) View.ALPHA, 1.0f));
            } else {
                this.containerCamera.setVisibility(0);
                this.avatarAnimation.playTogether(ObjectAnimator.ofFloat(this.containerCamera, (Property<View, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(this.ivAvatarProgress, (Property<RadialProgressView, Float>) View.ALPHA, 0.0f));
            }
            this.avatarAnimation.setDuration(180L);
            this.avatarAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity.2
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (ChangePersonalInformationActivity.this.avatarAnimation == null || ChangePersonalInformationActivity.this.containerCamera == null) {
                        return;
                    }
                    if (show) {
                        ChangePersonalInformationActivity.this.containerCamera.setVisibility(4);
                    } else {
                        ChangePersonalInformationActivity.this.ivAvatarProgress.setVisibility(4);
                    }
                    ChangePersonalInformationActivity.this.avatarAnimation = null;
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    ChangePersonalInformationActivity.this.avatarAnimation = null;
                }
            });
            this.avatarAnimation.start();
            return;
        }
        if (show) {
            this.containerCamera.setAlpha(1.0f);
            this.containerCamera.setVisibility(4);
            this.ivAvatarProgress.setAlpha(1.0f);
            this.ivAvatarProgress.setVisibility(0);
            return;
        }
        this.containerCamera.setAlpha(1.0f);
        this.containerCamera.setVisibility(0);
        this.ivAvatarProgress.setAlpha(0.0f);
        this.ivAvatarProgress.setVisibility(4);
    }

    private void onAuthSuccess(TLRPC.TL_auth_authorization res) {
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
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.appDidLogIn, new Object[0]);
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

    private void updateUserData(TLRPC.UserFull userFull, AlertDialog progressDialog) {
        TLRPC.User user;
        TLRPC.User newUser;
        if (userFull == null || (user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(UserConfig.getInstance(this.currentAccount).getClientUserId()))) == null || (newUser = userFull.user) == null) {
            return;
        }
        if (user != null) {
            user.first_name = newUser.first_name;
            user.last_name = newUser.last_name;
            user.photo = newUser.photo;
            if (user.photo != null) {
                if (user.photo.photo_small != null && this.avatar != null) {
                    File destFile = FileLoader.getPathToAttach(user.photo.photo_small, true);
                    File src = FileLoader.getPathToAttach(this.avatar, true);
                    src.renameTo(destFile);
                    String oldKey = this.avatar.volume_id + "_" + this.avatar.local_id + "@50_50";
                    String newKey = user.photo.photo_small.volume_id + "_" + user.photo.photo_small.local_id + "@50_50";
                    ImageLoader.getInstance().replaceImageInCache(oldKey, newKey, ImageLocation.getForUser(user, false), true);
                }
                if (user.photo.photo_big != null && this.avatarBig != null) {
                    File destFile2 = FileLoader.getPathToAttach(user.photo.photo_big, true);
                    File src2 = FileLoader.getPathToAttach(this.avatarBig, true);
                    src2.renameTo(destFile2);
                }
            }
            MessagesStorage.getInstance(this.currentAccount).clearUserPhotos(user.id);
            ArrayList<TLRPC.User> users = new ArrayList<>();
            users.add(user);
            MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(users, null, false, true);
        }
        if (user != null && (user.photo instanceof TLRPC.TL_userProfilePhoto)) {
            saveImage(progressDialog);
            return;
        }
        ToastUtils.show(R.string.SetupSuccess);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.updateInterfaces, Integer.valueOf(MessagesController.UPDATE_MASK_ALL));
        UserConfig.getInstance(this.currentAccount).saveConfig(true);
        finishFragment();
    }

    private void saveImage(final AlertDialog progressDialog) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$PcQn3EJ-KSswm5wrAwWrHISdZJs
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$saveImage$15$ChangePersonalInformationActivity(progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$saveImage$15$ChangePersonalInformationActivity(final AlertDialog progressDialog) {
        while (this.ivAvatar.getImageReceiver().getBitmap() == null) {
            try {
                Thread.sleep(10L);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        Bitmap bitmap = this.ivAvatar.getImageReceiver().getBitmap();
        File file = new File(AndroidUtilities.getCacheDir().getPath() + File.separator + "user_avatar.jpg");
        if (file.exists()) {
            file.delete();
        }
        FileOutputStream out = new FileOutputStream(file);
        bitmap.compress(Bitmap.CompressFormat.JPEG, 100, out);
        out.flush();
        out.close();
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$6-sjri83--Qzw_YaUtjTu0IOGPc
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$14$ChangePersonalInformationActivity(progressDialog);
            }
        });
    }

    public /* synthetic */ void lambda$null$14$ChangePersonalInformationActivity(AlertDialog progressDialog) {
        if (progressDialog != null) {
            progressDialog.dismiss();
        }
        ToastUtils.show(R.string.SetupSuccess);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.updateInterfaces, Integer.valueOf(MessagesController.UPDATE_MASK_ALL));
        UserConfig.getInstance(this.currentAccount).saveConfig(true);
        finishFragment();
    }

    private String clearEndOfStrSpace(String str) {
        if (str != null && str.length() > 0 && str.charAt(str.length() - 1) == ' ') {
            return clearEndOfStrSpace(str.substring(0, str.length() - 1));
        }
        return str;
    }

    private void parseError(TLRPC.TL_error error) {
        if (error.text.contains("PHONE_NUMBER_INVALID")) {
            needShowAlert(LocaleController.getString(R.string.InvalidPhoneNumber), true, null);
            return;
        }
        if (error.text.contains("PHONE_CODE_EMPTY") || error.text.contains("PHONE_CODE_INVALID")) {
            needShowAlert(LocaleController.getString(R.string.InvalidCode), true, null);
            finishFragment();
            return;
        }
        if (error.text.contains("FIRSTNAME_INVALID")) {
            needShowAlert(LocaleController.getString(R.string.InvalidName), true, null);
            return;
        }
        if (error.text.contains("LASTNAME_INVALID")) {
            needShowAlert(LocaleController.getString(R.string.InvalidNickname), true, null);
            return;
        }
        if (error.text.contains("FIRSTNAME_LASTNAME_EMPTY")) {
            needShowAlert(LocaleController.getString(R.string.EmptyNameTips), true, null);
            return;
        }
        if (error.text.contains("PHOTO_CHECK_FEAILED")) {
            needShowAlert(LocaleController.getString(R.string.FailedToSetAvatarVerification), true, null);
            return;
        }
        if (error.text.contains("ALREDY_CHANGE")) {
            needShowAlert(LocaleController.getString(R.string.InformationModified), true, null);
            return;
        }
        if (error.text.contains("NAME_TOO_LONG")) {
            needShowAlert(LocaleController.getString(R.string.NickNameIsTooLongAndPleaseTryAgainAfterModified), true, null);
            return;
        }
        if (error.text.contains("PHONE_NUMBER_OCCUPIED")) {
            needShowAlert(LocaleController.formatString("ChangePhoneNumberOccupied", R.string.ChangePhoneNumberOccupied, this.accoutName), true, null);
            return;
        }
        if (error.text.contains("PROXYCODE_INVALID")) {
            needShowAlert(LocaleController.getString("ProxyCodeInvalid", R.string.ProxyCodeInvalid), true, null);
            return;
        }
        if (error.text.contains("IPORDE_LIMIT")) {
            needShowAlert(LocaleController.getString("IpOrDeLimit", R.string.IpOrDeLimit), true, null);
            return;
        }
        if (error.text.equals("INTERNAL")) {
            needShowAlert(LocaleController.getString("InternalError", R.string.InternalError), true, null);
            return;
        }
        if (error.text.contains("FLOOD_WAIT")) {
            needShowAlert(LocaleController.getString(R.string.FloodWait), true, null);
        } else if (error.text.contains("UUID_REG_ERROR")) {
            needShowAlert(LocaleController.getString(R.string.NonRegisteredDeviceLogin), true, null);
        } else {
            needShowAlert(LocaleController.getString(R.string.OperationFailedPleaseTryAgain), true, null);
        }
    }

    private void needShowAlert(String text, boolean canCancel, DialogInterface.OnClickListener onClickListener) {
        if (text == null || getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString(R.string.AppName));
        builder.setMessage(text);
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), onClickListener);
        AlertDialog dialog = builder.create();
        dialog.setCancelable(canCancel);
        dialog.setCanceledOnTouchOutside(canCancel);
        showDialog(dialog);
    }

    private void loadCurrentState() {
        MryEditText mryEditText;
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("logininfo2", 0);
        String nickName = preferences.getString(getCurrentSpKey("user_name"), null);
        if (nickName != null && (mryEditText = this.etNickName) != null) {
            mryEditText.setText(nickName);
        }
        int i = preferences.getInt(getCurrentSpKey("user_birth"), 0);
        this.mBirth = i;
        MryTextView mryTextView = this.tvSelectDateOfBirth;
        if (mryTextView != null && i != 0) {
            mryTextView.setText(TimeUtils.millis2String(((long) this.mBirth) * 1000, "yyyy-MM-dd") + "");
        }
        this.mGender = preferences.getInt(getCurrentSpKey("user_gender"), 0);
        long user_avatar_id = preferences.getLong(getCurrentSpKey("user_avatar_id"), -1L);
        int user_avatar_parts = preferences.getInt(getCurrentSpKey("user_avatar_parts"), -1);
        String user_avatar_name = preferences.getString(getCurrentSpKey("user_avatar_name"), null);
        String user_avatar_md5_checksum = preferences.getString(getCurrentSpKey("user_avatar_md5_checksum"), null);
        String string = preferences.getString(getCurrentSpKey("current_select_photo_path"), null);
        this.mCurrentSelectPhotoPath = string;
        if (user_avatar_id != -1 && user_avatar_parts != -1 && user_avatar_name != null && user_avatar_md5_checksum != null && string != null) {
            if (this.mAvatarFile == null) {
                this.mAvatarFile = new TLRPC.TL_inputFile();
            }
            this.mAvatarFile.id = user_avatar_id;
            this.mAvatarFile.parts = user_avatar_parts;
            this.mAvatarFile.name = user_avatar_name;
            this.mAvatarFile.md5_checksum = user_avatar_md5_checksum;
        }
    }

    private void saveCurrentState() {
        if (this.mIsLoginSuccess || this.pwdHash == null) {
            return;
        }
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("logininfo2", 0);
        SharedPreferences.Editor editor = preferences.edit();
        if (this.etNickName != null) {
            if (!TextUtils.isEmpty(((Object) this.etNickName.getText()) + "")) {
                editor.putString(getCurrentSpKey("user_name"), this.etNickName.getText().toString().trim());
            }
        }
        if (this.mBirth != 0) {
            editor.putInt(getCurrentSpKey("user_birth"), this.mBirth);
        }
        if (this.mGender != 0) {
            editor.putInt(getCurrentSpKey("user_gender"), this.mGender);
        }
        if (this.mAvatarFile != null && this.mCurrentSelectPhotoPath != null) {
            editor.putLong(getCurrentSpKey("user_avatar_id"), this.mAvatarFile.id);
            editor.putInt(getCurrentSpKey("user_avatar_parts"), this.mAvatarFile.parts);
            editor.putString(getCurrentSpKey("user_avatar_name"), this.mAvatarFile.name);
            editor.putString(getCurrentSpKey("user_avatar_md5_checksum"), this.mAvatarFile.md5_checksum);
            editor.putString(getCurrentSpKey("current_select_photo_path"), this.mCurrentSelectPhotoPath);
        }
        editor.apply();
    }

    private void clearCurrentState() {
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("logininfo2", 0);
        SharedPreferences.Editor editor = preferences.edit();
        editor.clear();
        editor.apply();
    }

    private String getCurrentSpKey(String key) {
        if (this.accoutName == null) {
            return key;
        }
        return this.accoutName + key;
    }

    private void showSelectBirthDialog() {
        if (this.mTimePickerBuilder == null) {
            this.mTimePickerBuilder = TimeWheelPickerDialog.getDefaultBuilder(getParentActivity(), new OnTimeSelectListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$Q-mP7vl52ONwbumQ_2aHKvWFdOY
                @Override // com.bigkoo.pickerview.listener.OnTimeSelectListener
                public final void onTimeSelect(Date date, View view) {
                    this.f$0.lambda$showSelectBirthDialog$16$ChangePersonalInformationActivity(date, view);
                }
            });
        }
        if (!TextUtils.isEmpty(((Object) this.tvSelectDateOfBirth.getText()) + "")) {
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(TimeUtils.string2Date(this.tvSelectDateOfBirth.getText().toString().trim(), LocaleController.getString(R.string.formatterStandardYearMonthDay)));
            this.mTimePickerBuilder.setDate(calendar);
        } else {
            this.mTimePickerBuilder.setDate(Calendar.getInstance());
        }
        showDialog(this.mTimePickerBuilder.build());
    }

    public /* synthetic */ void lambda$showSelectBirthDialog$16$ChangePersonalInformationActivity(Date date, View v) {
        String dateStr = TimeUtils.date2String(date, "yyyy-MM-dd");
        this.tvSelectDateOfBirth.setText(dateStr);
        long mills = TimeUtils.string2Millis(dateStr, "yyyy-MM-dd");
        this.mBirth = (int) (mills / 1000);
        dismissCurrentDialog();
        changeBtnEnbale();
    }

    public void showSexSelectDialog() {
        if (this.mGenderPickerBulder == null) {
            List<String> data = new ArrayList<>(Arrays.asList(LocaleController.getString(R.string.PassportFemale), LocaleController.getString(R.string.PassportMale)));
            OptionsWheelPickerDialog.Builder<String> defaultBuilder = OptionsWheelPickerDialog.getDefaultBuilder(getParentActivity(), new OnOptionsSelectListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$P8pp88GQXNyX_4pK4dPvn0h-4p8
                @Override // com.bigkoo.pickerview.listener.OnOptionsSelectListener
                public final void onOptionsSelect(int i, int i2, int i3, View view) {
                    this.f$0.lambda$showSexSelectDialog$17$ChangePersonalInformationActivity(i, i2, i3, view);
                }
            });
            this.mGenderPickerBulder = defaultBuilder;
            defaultBuilder.setPicker(data);
        }
        showDialog(this.mGenderPickerBulder.build());
    }

    public /* synthetic */ void lambda$showSexSelectDialog$17$ChangePersonalInformationActivity(int options1, int options2, int options3, View v) {
        int i = options1 == 0 ? 2 : 1;
        this.mGender = i;
        this.tvSelectSex.setText(LocaleController.getString(i == 2 ? R.string.PassportFemale : R.string.PassportMale));
        changeBtnEnbale();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void changeBtnEnbale() {
        MryEditText mryEditText;
        if (this.btnDone == null || (mryEditText = this.etNickName) == null) {
            return;
        }
        boolean tag = true;
        if (this.isRegisterUser) {
            if (this.accoutName != null && this.pwdHash != null && (mryEditText == null || mryEditText.getText() == null || this.etNickName.length() == 0)) {
                tag = false;
            }
        } else if (this.mUser != null && (mryEditText == null || mryEditText.getText() == null || this.etNickName.length() == 0)) {
            tag = false;
        }
        this.btnDone.setEnabled(tag);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean back() {
        if (!this.mCanGoBack) {
            return true;
        }
        if (this.mAvatarFile == null && this.mBirth == 0 && this.mGender == 0) {
            if (TextUtils.isEmpty(((Object) this.etNickName.getText()) + "")) {
                return false;
            }
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(LocaleController.getString("AreYouSureRegistration", R.string.AreYouSureRegistration));
        builder.setNegativeButton(LocaleController.getString("Stop", R.string.Stop), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$ChangePersonalInformationActivity$-pVRNGRSf81RRbucZHYmiAYKAuc
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$back$18$ChangePersonalInformationActivity(dialogInterface, i);
            }
        });
        builder.setPositiveButton(LocaleController.getString("Continue", R.string.Continue), null);
        showDialog(builder.create());
        return true;
    }

    public /* synthetic */ void lambda$back$18$ChangePersonalInformationActivity(DialogInterface dialogInterface, int i) {
        saveCurrentState();
        finishFragment();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected AnimatorSet onCustomTransitionAnimation(final boolean isOpen, final Runnable callback) {
        AnimatorSet set = new AnimatorSet();
        final int parentHeight = getParentLayout().getHeight();
        final int actionBarHeight = this.actionBar.getHeight();
        if (isOpen) {
            set.playTogether(ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.TRANSLATION_Y, parentHeight, 0.0f), ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.ALPHA, 0.0f, 1.0f), ObjectAnimator.ofFloat(this.fragmentView, (Property<View, Float>) View.TRANSLATION_Y, parentHeight + actionBarHeight, 0.0f), ObjectAnimator.ofFloat(this.fragmentView, (Property<View, Float>) View.ALPHA, 0.0f, 1.0f));
        } else {
            set.playTogether(ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.TRANSLATION_Y, 0.0f, parentHeight), ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.ALPHA, 1.0f, 0.0f), ObjectAnimator.ofFloat(this.fragmentView, (Property<View, Float>) View.TRANSLATION_Y, 0.0f, parentHeight + actionBarHeight), ObjectAnimator.ofFloat(this.fragmentView, (Property<View, Float>) View.ALPHA, 1.0f, 0.0f));
        }
        set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity.3
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                super.onAnimationEnd(animation);
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animation) {
                super.onAnimationStart(animation);
                if (isOpen) {
                    ChangePersonalInformationActivity.this.actionBar.setTranslationY(parentHeight);
                    ChangePersonalInformationActivity.this.fragmentView.setTranslationY(parentHeight + actionBarHeight);
                }
            }
        });
        set.setInterpolator(new AccelerateDecelerateInterpolator());
        set.setDuration(300L);
        set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity.4
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                Runnable runnable = callback;
                if (runnable != null) {
                    runnable.run();
                }
            }
        });
        set.start();
        return set;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        if (back()) {
            return false;
        }
        return super.onBackPressed();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle args) {
        ImageUpdater imageUpdater = this.mImageUpdater;
        if (imageUpdater != null && imageUpdater.currentPicturePath != null) {
            args.putString("path", this.mImageUpdater.currentPicturePath);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void restoreSelfArgs(Bundle args) {
        ImageUpdater imageUpdater = this.mImageUpdater;
        if (imageUpdater != null) {
            imageUpdater.currentPicturePath = args.getString("path");
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean canBeginSlide() {
        return false;
    }
}
