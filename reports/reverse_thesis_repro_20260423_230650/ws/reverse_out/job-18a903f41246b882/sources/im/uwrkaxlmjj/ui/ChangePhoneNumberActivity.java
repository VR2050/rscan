package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.CountDownTimer;
import android.text.Editable;
import android.text.InputFilter;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import butterknife.BindView;
import butterknife.OnClick;
import com.google.android.exoplayer2.upstream.DefaultLoadErrorHandlingPolicy;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.DrawableUtils;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.CountrySelectActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class ChangePhoneNumberActivity extends BaseFragment {
    private TextWatcher codeWatcher;

    @BindView(R.attr.btn_submit)
    MryRoundButton mBtnSubmit;

    @BindView(R.attr.et_code)
    MryEditText mEtCode;

    @BindView(R.attr.et_phone_number)
    MryEditText mEtPhoneNumber;

    @BindView(R.attr.iv_clear)
    ImageView mIvClear;

    @BindView(R.attr.ll_code_container)
    LinearLayout mLlCodeContainer;

    @BindView(R.attr.ll_phone_container)
    LinearLayout mLlPhoneContainer;

    @BindView(R.attr.tv_country_code)
    MryTextView mTvCountryCode;

    @BindView(R.attr.tv_send_code)
    MryTextView mTvSendCode;
    private String phoneHash;
    private TextWatcher phoneNumberWatcher;
    private ArrayList<String> countriesArray = new ArrayList<>();
    private HashMap<String, String> countriesMap = new HashMap<>();
    private HashMap<String, String> codesMap = new HashMap<>();
    private HashMap<String, String> phoneFormatMap = new HashMap<>();
    private CountDownTimer mTimer = new CountDownTimer(DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS, 1000) { // from class: im.uwrkaxlmjj.ui.ChangePhoneNumberActivity.5
        @Override // android.os.CountDownTimer
        public void onTick(long millisUntilFinished) {
            ChangePhoneNumberActivity.this.mTvSendCode.setText((millisUntilFinished / 1000) + "s后重发");
            ChangePhoneNumberActivity.this.mTvSendCode.setTextColor(-12862209);
            ChangePhoneNumberActivity.this.mTvSendCode.setEnabled(false);
        }

        @Override // android.os.CountDownTimer
        public void onFinish() {
            ChangePhoneNumberActivity.this.mTvSendCode.setText(LocaleController.getString("GetPhoneCode", R.string.GetPhoneCode));
            ChangePhoneNumberActivity.this.mTvSendCode.setTextColor(Theme.ACTION_BAR_MEDIA_PICKER_COLOR);
            ChangePhoneNumberActivity.this.mTvSendCode.setEnabled(true);
        }
    };

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_change_phone_number, (ViewGroup) null);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        useButterKnife();
        initView();
        initData();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString(R.string.ChangePhoneNumber2));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.ChangePhoneNumberActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    ChangePhoneNumberActivity.this.finishFragment();
                }
            }
        });
    }

    private void initView() {
        this.mLlPhoneContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.mLlCodeContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        MryEditText mryEditText = this.mEtPhoneNumber;
        TextWatcher textWatcher = new TextWatcher() { // from class: im.uwrkaxlmjj.ui.ChangePhoneNumberActivity.2
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                ChangePhoneNumberActivity.this.mIvClear.setVisibility(TextUtils.isEmpty(s) ? 8 : 0);
                ChangePhoneNumberActivity.this.checkBntEnable();
            }
        };
        this.phoneNumberWatcher = textWatcher;
        mryEditText.addTextChangedListener(textWatcher);
        MryEditText mryEditText2 = this.mEtCode;
        TextWatcher textWatcher2 = new TextWatcher() { // from class: im.uwrkaxlmjj.ui.ChangePhoneNumberActivity.3
            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                ChangePhoneNumberActivity.this.checkBntEnable();
            }
        };
        this.codeWatcher = textWatcher2;
        mryEditText2.addTextChangedListener(textWatcher2);
        this.mBtnSubmit.setPrimaryRadiusAdjustBoundsFillStyle();
        this.mBtnSubmit.setBackgroundColor(-12862209);
    }

    /* JADX WARN: Can't wrap try/catch for region: R(10:0|2|(2:31|3)|(7:4|(3:6|(2:8|34)(1:35)|9)(1:33)|14|29|15|(2:17|18)|(1:37)(2:25|(2:27|28)(1:38)))|10|14|29|15|(0)|(2:23|37)(1:36)) */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0086, code lost:
    
        r4 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x0087, code lost:
    
        im.uwrkaxlmjj.messenger.FileLog.e(r4);
     */
    /* JADX WARN: Removed duplicated region for block: B:17:0x007c A[Catch: Exception -> 0x0086, TRY_LEAVE, TryCatch #0 {Exception -> 0x0086, blocks: (B:15:0x0070, B:17:0x007c), top: B:29:0x0070 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void initData() {
        /*
            Method dump skipped, instruction units count: 228
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.ChangePhoneNumberActivity.initData():void");
    }

    private void check(boolean sendMsg) {
        boolean tag = false;
        if (!TextUtils.isEmpty(this.mTvCountryCode.getText())) {
            String coutryCode = this.mTvCountryCode.getText().toString().trim();
            if (TextUtils.isEmpty(coutryCode.replaceAll("\\+", ""))) {
                tag = true;
            }
        }
        if (tag) {
            ToastUtils.show(R.string.ReminderPleaseSelectCountry);
        } else if (sendMsg) {
            sendSms();
        } else {
            submit();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkBntEnable() {
        boolean tag = false;
        if (!TextUtils.isEmpty(this.mTvCountryCode.getText())) {
            String coutryCode = this.mTvCountryCode.getText().toString().trim();
            if (!TextUtils.isEmpty(coutryCode.replaceAll("\\+", ""))) {
                tag = true;
            }
        }
        this.mBtnSubmit.setEnabled((!tag || TextUtils.isEmpty(this.mEtPhoneNumber.getText()) || TextUtils.isEmpty(this.mEtCode.getText())) ? false : true);
    }

    private void sendSms() {
        final String phoneNumber = this.mEtPhoneNumber.getText().toString().trim();
        String countryCode = this.mTvCountryCode.getText().toString();
        if (TextUtils.isEmpty(countryCode)) {
            ToastUtils.show(R.string.WrongCountry);
            this.mLlPhoneContainer.setBackground(DrawableUtils.createLayerDrawable(Theme.getColor(Theme.key_windowBackgroundWhite), -570319, AndroidUtilities.dp(5.0f)));
            this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$5bkSGPssYnhZiKm6nloqZQbjQwY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$sendSms$0$ChangePhoneNumberActivity();
                }
            }, 3000L);
            return;
        }
        if (TextUtils.isEmpty(phoneNumber)) {
            ToastUtils.show(R.string.InvalidPhoneNumberTips);
            this.mLlPhoneContainer.setBackground(DrawableUtils.createLayerDrawable(Theme.getColor(Theme.key_windowBackgroundWhite), -570319, AndroidUtilities.dp(5.0f)));
            this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$KV-07cWjDAo8OBtF0HjrzeV92c4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$sendSms$1$ChangePhoneNumberActivity();
                }
            }, 3000L);
            return;
        }
        String phone = countryCode.replace(Marker.ANY_NON_NULL_MARKER, "") + phoneNumber;
        if (getUserConfig() != null && getUserConfig().getClientPhone() != null && getUserConfig().getClientPhone().equals(phone)) {
            ToastUtils.show(R.string.CannotMatchTheCurrentPhoneNumber);
            this.mLlPhoneContainer.setBackground(DrawableUtils.createLayerDrawable(Theme.getColor(Theme.key_windowBackgroundWhite), -570319, AndroidUtilities.dp(5.0f)));
            this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$9ifSbFKNiGvttC5K17hRpQKWEpo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$sendSms$2$ChangePhoneNumberActivity();
                }
            }, 3000L);
            return;
        }
        TLRPC.TL_account_sendChangePhoneCode req = new TLRPC.TL_account_sendChangePhoneCode();
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
        final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$L856kcT8gEMuz5xM-LPizYCl43Y
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$sendSms$5$ChangePhoneNumberActivity(progressDialog, phoneNumber, tLObject, tL_error);
            }
        }, 2);
        ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$zxZU-UJnXTr16oN7yp0qv6WWnLQ
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$sendSms$6$ChangePhoneNumberActivity(reqId, dialogInterface);
            }
        });
        progressDialog.show();
    }

    public /* synthetic */ void lambda$sendSms$0$ChangePhoneNumberActivity() {
        this.mLlPhoneContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    public /* synthetic */ void lambda$sendSms$1$ChangePhoneNumberActivity() {
        this.mLlPhoneContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    public /* synthetic */ void lambda$sendSms$2$ChangePhoneNumberActivity() {
        this.mLlPhoneContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    public /* synthetic */ void lambda$sendSms$5$ChangePhoneNumberActivity(final XAlertDialog progressDialog, final String phoneNumber, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$903OeXo1rNNjwDOSBqUm8SenjZM
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$4$ChangePhoneNumberActivity(progressDialog, error, response, phoneNumber);
            }
        });
    }

    public /* synthetic */ void lambda$null$4$ChangePhoneNumberActivity(XAlertDialog progressDialog, TLRPC.TL_error error, TLObject response, String phoneNumber) {
        progressDialog.dismiss();
        if (error == null) {
            TLRPC.TL_auth_sentCode res = (TLRPC.TL_auth_sentCode) response;
            this.phoneHash = res.phone_code_hash;
            this.mTimer.start();
            ToastUtils.show((CharSequence) LocaleController.getString("SendSuccess", R.string.SendSuccess));
            return;
        }
        if (error.text.contains("PHONE_NUMBER_INVALID")) {
            ToastUtils.show(R.string.InvalidPhoneNumberTips);
            this.mLlPhoneContainer.setBackground(DrawableUtils.createLayerDrawable(Theme.getColor(Theme.key_windowBackgroundWhite), -570319, AndroidUtilities.dp(5.0f)));
            this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$2OovQ45rp8xB3YZGzCwvet2eBwg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$3$ChangePhoneNumberActivity();
                }
            }, 3000L);
            return;
        }
        if (error.text.contains("PHONE_CODE_EMPTY") || error.text.contains("PHONE_CODE_INVALID")) {
            ToastUtils.show(R.string.InvalidCode);
            return;
        }
        if (error.text.contains("PHONE_CODE_EXPIRED")) {
            ToastUtils.show(R.string.CodeExpired);
            return;
        }
        if (error.text.startsWith("FLOOD_WAIT")) {
            ToastUtils.show(R.string.FloodWait);
            return;
        }
        if (error.text.startsWith("PHONE_NUMBER_OCCUPIED")) {
            ToastUtils.show((CharSequence) LocaleController.formatString("ChangePhoneNumberOccupied", R.string.ChangePhoneNumberOccupied, phoneNumber));
            return;
        }
        if (error.text.contains("IPORDE_LIMIT")) {
            ToastUtils.show((CharSequence) LocaleController.getString("IpOrDeLimit", R.string.IpOrDeLimit));
        } else if (error.text.equals("INTERNAL")) {
            ToastUtils.show((CharSequence) LocaleController.getString("InternalError", R.string.InternalError));
        } else {
            ToastUtils.show(R.string.ErrorOccurred);
        }
    }

    public /* synthetic */ void lambda$null$3$ChangePhoneNumberActivity() {
        this.mLlPhoneContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    public /* synthetic */ void lambda$sendSms$6$ChangePhoneNumberActivity(int reqId, DialogInterface dialog) {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequest(reqId, true);
    }

    private void submit() {
        String phoneNumber = this.mEtPhoneNumber.getText().toString().trim();
        String countryCode = this.mTvCountryCode.getText().toString();
        TLRPC.TL_account_changePhone req = new TLRPC.TL_account_changePhone();
        req.phone_number = countryCode.replace(Marker.ANY_NON_NULL_MARKER, "") + " " + phoneNumber;
        req.phone_code = this.mEtCode.getText().toString().trim();
        req.phone_code_hash = this.phoneHash;
        final XAlertDialog progressDialog = new XAlertDialog(getParentActivity(), 4);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$4qWhmtUzPxz5DpibD_Jh17MQTPM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$submit$10$ChangePhoneNumberActivity(progressDialog, tLObject, tL_error);
            }
        }, 2);
        ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$YgrzyHhp9Vzj4f_IFHBzLVVr7Bg
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$submit$11$ChangePhoneNumberActivity(reqId, dialogInterface);
            }
        });
        progressDialog.show();
    }

    public /* synthetic */ void lambda$submit$10$ChangePhoneNumberActivity(final XAlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$UTHO9wqUvGf2bbCpuNQZ5eyTyc8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$9$ChangePhoneNumberActivity(progressDialog, error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$9$ChangePhoneNumberActivity(XAlertDialog progressDialog, TLRPC.TL_error error, TLObject response) {
        progressDialog.dismiss();
        if (error == null) {
            TLRPC.User user = (TLRPC.User) response;
            UserConfig.getInstance(this.currentAccount).setCurrentUser(user);
            UserConfig.getInstance(this.currentAccount).saveConfig(true);
            ArrayList<TLRPC.User> users = new ArrayList<>();
            users.add(user);
            MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(users, null, true, true);
            MessagesController.getInstance(this.currentAccount).putUser(user, false);
            finishFragment();
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
            return;
        }
        if (error.text.contains("PHONE_NUMBER_INVALID")) {
            ToastUtils.show(R.string.InvalidPhoneNumberTips);
            this.mLlPhoneContainer.setBackground(DrawableUtils.createLayerDrawable(Theme.getColor(Theme.key_windowBackgroundWhite), -570319, AndroidUtilities.dp(5.0f)));
            this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$rLAZ2xwqImuVIPRa-PtasyLV9Eg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$7$ChangePhoneNumberActivity();
                }
            }, 3000L);
        } else if (error.text.contains("PHONE_CODE_EMPTY") || error.text.contains("PHONE_CODE_INVALID")) {
            ToastUtils.show(R.string.VerificationCodeError);
            this.mLlCodeContainer.setBackground(DrawableUtils.createLayerDrawable(Theme.getColor(Theme.key_windowBackgroundWhite), -570319, AndroidUtilities.dp(5.0f)));
            this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$DprrB3gvBf-Zi20rNLGBElYydiw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$8$ChangePhoneNumberActivity();
                }
            }, 3000L);
        } else if (error.text.contains("PHONE_CODE_EXPIRED")) {
            ToastUtils.show(R.string.CodeExpired);
        } else if (error.text.startsWith("FLOOD_WAIT")) {
            ToastUtils.show(R.string.FloodWait);
        } else {
            ToastUtils.show((CharSequence) error.text);
        }
    }

    public /* synthetic */ void lambda$null$7$ChangePhoneNumberActivity() {
        this.mLlPhoneContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    public /* synthetic */ void lambda$null$8$ChangePhoneNumberActivity() {
        this.mLlCodeContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    public /* synthetic */ void lambda$submit$11$ChangePhoneNumberActivity(int reqId, DialogInterface dialog) {
        ConnectionsManager.getInstance(this.currentAccount).cancelRequest(reqId, true);
    }

    @OnClick({R.attr.tv_country_code, R.attr.iv_clear, R.attr.tv_send_code, R.attr.btn_submit})
    public void onViewClicked(View view) {
        switch (view.getId()) {
            case R.attr.btn_submit /* 2131296436 */:
                check(false);
                break;
            case R.attr.iv_clear /* 2131296791 */:
                MryEditText mryEditText = this.mEtPhoneNumber;
                if (mryEditText != null) {
                    mryEditText.setText((CharSequence) null);
                }
                break;
            case R.attr.tv_country_code /* 2131297739 */:
                CountrySelectActivity fragment = new CountrySelectActivity(true);
                fragment.setCountrySelectActivityDelegate(new CountrySelectActivity.CountrySelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$ChangePhoneNumberActivity$M4ate6RDNgoRHa7M6MqwKROFT1c
                    @Override // im.uwrkaxlmjj.ui.CountrySelectActivity.CountrySelectActivityDelegate
                    public final void didSelectCountry(CountrySelectActivity.Country country) {
                        this.f$0.lambda$onViewClicked$12$ChangePhoneNumberActivity(country);
                    }
                });
                presentFragment(fragment);
                break;
            case R.attr.tv_send_code /* 2131297833 */:
                check(true);
                break;
        }
    }

    public /* synthetic */ void lambda$onViewClicked$12$ChangePhoneNumberActivity(CountrySelectActivity.Country country) {
        this.mTvCountryCode.setText(Marker.ANY_NON_NULL_MARKER + country.code);
        this.mEtPhoneNumber.setFilters(new InputFilter[]{new InputFilter.LengthFilter(country.phoneFormat.replace(" ", "").length()) { // from class: im.uwrkaxlmjj.ui.ChangePhoneNumberActivity.6
        }});
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        TextWatcher textWatcher;
        TextWatcher textWatcher2;
        MryEditText mryEditText = this.mEtPhoneNumber;
        if (mryEditText != null && (textWatcher2 = this.phoneNumberWatcher) != null) {
            mryEditText.removeTextChangedListener(textWatcher2);
        }
        MryEditText mryEditText2 = this.mEtCode;
        if (mryEditText2 != null && (textWatcher = this.codeWatcher) != null) {
            mryEditText2.removeTextChangedListener(textWatcher);
        }
        CountDownTimer countDownTimer = this.mTimer;
        if (countDownTimer != null) {
            countDownTimer.cancel();
            this.mTimer = null;
        }
        super.onFragmentDestroy();
    }
}
