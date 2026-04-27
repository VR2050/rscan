package im.uwrkaxlmjj.ui;

import android.app.ActivityManager;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.text.TextPaint;
import android.text.style.ClickableSpan;
import android.view.View;
import android.view.Window;
import androidx.appcompat.app.AppCompatActivity;
import com.blankj.utilcode.util.SpanUtils;
import com.google.android.gms.common.internal.ImagesContract;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.constants.Constants;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.hui.WebViewAppCompatActivity;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class LaunchAgDialogActivity extends AppCompatActivity {
    private boolean startPressed;

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (Build.VERSION.SDK_INT >= 21) {
            Window window = getWindow();
            window.getDecorView().setSystemUiVisibility(1280);
            window.setStatusBarColor(0);
        }
        try {
            getWindow().clearFlags(8192);
        } catch (Exception e) {
            FileLog.e(e);
        }
        showPrivacyPermissionDialog();
    }

    private void showPrivacyPermissionDialog() {
        SharedPreferences sp = MessagesController.getGlobalMainSettings();
        if (!sp.getBoolean("isFSPrivacy", true)) {
            toLaunchPage();
            return;
        }
        WalletDialog dialog = new WalletDialog(this);
        dialog.setCancelable(false);
        dialog.setCanceledOnTouchOutside(false);
        SpanUtils span = new SpanUtils();
        span.append(LocaleController.getString(R.string.PrivacyAgreement1)).append(LocaleController.getString(R.string.UserAgreementOnly)).setClickSpan(new ClickableSpan() { // from class: im.uwrkaxlmjj.ui.LaunchAgDialogActivity.2
            @Override // android.text.style.ClickableSpan
            public void onClick(View widget) {
                Intent intent = new Intent(LaunchAgDialogActivity.this, (Class<?>) WebViewAppCompatActivity.class);
                intent.putExtra(ImagesContract.URL, Constants.URL_USER_AGREEMENT);
                LaunchAgDialogActivity.this.startActivity(intent);
            }

            @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
            public void updateDrawState(TextPaint ds) {
                super.updateDrawState(ds);
                ds.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
            }
        }).append("、").append(LocaleController.getString(R.string.PrivacyAgreement)).setClickSpan(new ClickableSpan() { // from class: im.uwrkaxlmjj.ui.LaunchAgDialogActivity.1
            @Override // android.text.style.ClickableSpan
            public void onClick(View widget) {
                Intent intent = new Intent(LaunchAgDialogActivity.this, (Class<?>) WebViewAppCompatActivity.class);
                intent.putExtra(ImagesContract.URL, Constants.URL_PRIVACY_POLICY);
                LaunchAgDialogActivity.this.startActivity(intent);
            }

            @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
            public void updateDrawState(TextPaint ds) {
                super.updateDrawState(ds);
                ds.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
            }
        }).append(LocaleController.getString(R.string.PrivacyAgreement2));
        dialog.setMessage(span.create(), false, false);
        dialog.setTitle(LocaleController.getString(R.string.PrivacyAgreement));
        dialog.setNegativeButton(LocaleController.getString(R.string.Disagree), Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.LaunchAgDialogActivity.3
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog2, int which) {
                LaunchAgDialogActivity.this.finish();
            }
        });
        dialog.setPositiveButton(LocaleController.getString(R.string.Agree), Theme.getColor(Theme.key_windowBackgroundWhiteBlueText), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.LaunchAgDialogActivity.4
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog2, int which) {
                if (!LaunchAgDialogActivity.this.startPressed) {
                    LaunchAgDialogActivity.this.setNotFirstLaunch();
                    LaunchAgDialogActivity.this.startPressed = true;
                    LaunchAgDialogActivity.this.toLaunchPage();
                }
            }
        });
        dialog.show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void toLaunchPage() {
        Intent intent2 = new Intent(this, (Class<?>) LaunchActivity.class);
        intent2.putExtra("fromIntro", true);
        startActivity(intent2);
        finish();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setNotFirstLaunch() {
        SharedPreferences sp = MessagesController.getGlobalMainSettings();
        if (sp.getBoolean("isFSPrivacy", true)) {
            SharedPreferences.Editor editor = sp.edit();
            editor.putBoolean("isFSPrivacy", false);
            editor.commit();
        }
    }

    public void killAppProcess() {
        ActivityManager mActivityManager = (ActivityManager) getSystemService("activity");
        List<ActivityManager.RunningAppProcessInfo> mList = mActivityManager.getRunningAppProcesses();
        for (ActivityManager.RunningAppProcessInfo runningAppProcessInfo : mList) {
            if (runningAppProcessInfo.pid != Process.myPid()) {
                Process.killProcess(runningAppProcessInfo.pid);
            }
        }
        Process.killProcess(Process.myPid());
        System.exit(0);
    }
}
