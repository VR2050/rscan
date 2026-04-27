package im.uwrkaxlmjj.ui;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import com.google.android.exoplayer2.C;

/* JADX INFO: loaded from: classes5.dex */
public class LaunchTempActivity extends AppCompatActivity {
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent remoteIntent = getIntent();
        Intent target = new Intent();
        target.setFlags(C.ENCODING_PCM_MU_LAW);
        target.setClass(this, LaunchActivity.class);
        target.setAction(remoteIntent.getAction());
        target.setData(remoteIntent.getData());
        startActivity(target);
        finish();
    }
}
