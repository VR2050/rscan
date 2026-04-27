package im.uwrkaxlmjj.ui.hui.login;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.net.Uri;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import com.alibaba.fastjson.JSONObject;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.network.OSSChat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCLogin;
import im.uwrkaxlmjj.ui.ExternalActionActivity;
import im.uwrkaxlmjj.ui.IndexActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.AppTextView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.utils.DeviceUtils;
import im.uwrkaxlmjj.utils.FingerprintUtil;
import java.util.ArrayList;
import java.util.Locale;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class LoginActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    public TextView backupIpAddressLog;
    private AppTextView tvTips;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.getBackupIpStatus);
        return super.onFragmentCreate();
    }

    private boolean checkPermission() {
        if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission("android.permission.READ_PHONE_STATE") != 0) {
            getParentActivity().requestPermissions(new String[]{"android.permission.READ_PHONE_STATE"}, 6);
            return false;
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_login_layout, (ViewGroup) null);
        this.actionBar.setAddToContainer(false);
        this.fragmentView.findViewById(R.attr.tv_service).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginActivity$zRKUSAcuPGmQq-UMh_8-9IR19xg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$0$LoginActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.tv_service).setVisibility(BuildVars.ENABLE_ME_ONLINE_SERVICE ? 0 : 8);
        this.tvTips = (AppTextView) this.fragmentView.findViewById(R.attr.tvTips);
        TextView textView = new TextView(context);
        this.backupIpAddressLog = textView;
        textView.setTextColor(getParentActivity().getResources().getColor(R.color.black));
        this.backupIpAddressLog.setTextSize(1, 10.0f);
        ((FrameLayout) this.fragmentView).addView(this.backupIpAddressLog, LayoutHelper.createFrame(-1, -1, 16, 160, 16, 16));
        login2();
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$0$LoginActivity(View view) {
        getServerUrl();
    }

    private void getServerUrl() {
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        showDialog(progressDialog);
        OSSChat.getInstance().sendOSSRequest(new OSSChat.OSSChatCallback() { // from class: im.uwrkaxlmjj.ui.hui.login.LoginActivity.1
            @Override // im.uwrkaxlmjj.network.OSSChat.OSSChatCallback
            public void onSuccess(String url) {
                progressDialog.dismiss();
                Log.d("bond", "客服链接 = " + url);
                Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(url));
                intent.putExtra("create_new_tab", true);
                intent.putExtra("com.android.browser.application_id", LoginActivity.this.getParentActivity().getPackageName());
                LoginActivity.this.getParentActivity().startActivity(intent);
            }

            @Override // im.uwrkaxlmjj.network.OSSChat.OSSChatCallback
            public void onFail() {
                progressDialog.dismiss();
                ToastUtils.show((CharSequence) "获取客服链接失败");
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResultFragment(requestCode, permissions, grantResults);
        if (requestCode == 6 && grantResults != null && grantResults[0] == 0) {
            login2();
        }
    }

    private void login2() {
        String oldFingerprint = DeviceUtils.getDeviceId2(getParentActivity());
        final String newFingerprint = FingerprintUtil.getDeviceId(getParentActivity());
        TLRPCLogin.TL_auth_SignAuto2 req = new TLRPCLogin.TL_auth_SignAuto2();
        String uuid = DeviceUtils.getDeviceId(getParentActivity());
        req.phone_uuid = uuid;
        req.ip = uuid;
        req.company_tag = "Sbcc";
        req.device_old = oldFingerprint;
        req.device_new = newFingerprint;
        Log.d("bond", "oldFingerprint = " + oldFingerprint + " ---- newFingerprint = " + newFingerprint);
        ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginActivity$VnXJvJ_SIOvYJMlShGenkk6w_EA
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$login2$2$LoginActivity(newFingerprint, tLObject, tL_error);
            }
        }, 10), this.classGuid);
    }

    public /* synthetic */ void lambda$login2$2$LoginActivity(final String newFingerprint, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginActivity$9rw0JzQRul2IIoGlPxPSjbfIIec
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$LoginActivity(error, response, newFingerprint);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$LoginActivity(TLRPC.TL_error error, TLObject response, String newFingerprint) {
        if (error == null) {
            if (!(response instanceof TLRPC.TL_auth_authorizationSignUpRequired) && (response instanceof TLRPC.TL_auth_authorization)) {
                Log.e("debug", "response" + JSONObject.toJSONString(response));
                onAuthSuccess((TLRPC.TL_auth_authorization) response);
                SharedPreferences sharedPreferences = ApplicationLoader.applicationContext.getSharedPreferences("deviceConfig", 0);
                sharedPreferences.edit().putString("device_fingerprint", newFingerprint).commit();
                return;
            }
            return;
        }
        parseError(error, "");
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        getConnectionsManager().cancelRequestsForGuid(this.classGuid);
    }

    protected void onAuthSuccess(TLRPC.TL_auth_authorization res) {
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
        if (getParentActivity() instanceof LaunchActivity) {
            presentFragment(new IndexActivity(), true);
            NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.mainUserInfoChanged, new Object[0]);
        } else if (getParentActivity() instanceof ExternalActionActivity) {
            ((ExternalActionActivity) getParentActivity()).onFinishLogin();
        }
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
            if (error.text.contains("PHONE_NUMBER_BANNED") || error.text.contains("ACCOUNT_RESTRICTED")) {
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
        builder.setNeutralButton(LocaleController.getString(R.string.BotHelp), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.login.-$$Lambda$LoginActivity$PGIEGai3x13soGsM85FR1IlT-yg
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$needShowInvalidAlert$3$LoginActivity(banned, phoneNumber, dialogInterface, i);
            }
        });
        builder.setPositiveButton(LocaleController.getString(R.string.OK), null);
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$needShowInvalidAlert$3$LoginActivity(boolean banned, String phoneNumber, DialogInterface dialog, int which) {
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

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.getBackupIpStatus) {
            Log.e("debug", "args==" + ((String) args[0]));
            if (this.backupIpAddressLog != null && getParentActivity() != null) {
                this.backupIpAddressLog.setText(((String) args[0]) + "（" + AndroidUtilities.getVersionName(getParentActivity()) + "）");
            }
        }
    }
}
