package im.uwrkaxlmjj.messenger;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import im.uwrkaxlmjj.ui.LaunchActivity;

/* JADX INFO: loaded from: classes2.dex */
public class OpenChatReceiver extends Activity {
    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent intent = getIntent();
        if (intent == null) {
            finish();
        }
        if (intent.getAction() == null || !intent.getAction().startsWith("com.tmessages.openchat")) {
            finish();
            return;
        }
        try {
            int chatId = intent.getIntExtra("chatId", 0);
            int userId = intent.getIntExtra("userId", 0);
            int encId = intent.getIntExtra("encId", 0);
            if (chatId == 0 && userId == 0 && encId == 0) {
                return;
            }
            Intent intent2 = new Intent(this, (Class<?>) LaunchActivity.class);
            intent2.setAction(intent.getAction());
            intent2.putExtras(intent);
            startActivity(intent2);
            finish();
        } catch (Throwable th) {
        }
    }
}
