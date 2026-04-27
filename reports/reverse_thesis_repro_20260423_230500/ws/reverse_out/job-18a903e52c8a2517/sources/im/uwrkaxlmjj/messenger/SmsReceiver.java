package im.uwrkaxlmjj.messenger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.TextUtils;
import com.google.android.gms.auth.api.phone.SmsRetriever;
import com.king.zxing.util.LogUtils;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes2.dex */
public class SmsReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        if (intent != null) {
            String message = "";
            try {
                SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", 0);
                String hash = preferences.getString("sms_hash", null);
                if (SmsRetriever.SMS_RETRIEVED_ACTION.equals(intent.getAction())) {
                    if (!AndroidUtilities.isWaitingForSms()) {
                        return;
                    }
                    Bundle bundle = intent.getExtras();
                    message = (String) bundle.get(SmsRetriever.EXTRA_SMS_MESSAGE);
                }
                if (TextUtils.isEmpty(message)) {
                    return;
                }
                Pattern pattern = Pattern.compile("[0-9\\-]+");
                Matcher matcher = pattern.matcher(message);
                if (matcher.find()) {
                    final String code = matcher.group(0).replace("-", "");
                    if (code.length() >= 3) {
                        if (preferences != null && hash != null) {
                            preferences.edit().putString("sms_hash_code", hash + LogUtils.VERTICAL + code).commit();
                        }
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$SmsReceiver$4YhwXOahw877awNlbpdvJpoKzLs
                            @Override // java.lang.Runnable
                            public final void run() {
                                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.didReceiveSmsCode, code);
                            }
                        });
                    }
                }
            } catch (Throwable e) {
                FileLog.e(e);
            }
        }
    }
}
