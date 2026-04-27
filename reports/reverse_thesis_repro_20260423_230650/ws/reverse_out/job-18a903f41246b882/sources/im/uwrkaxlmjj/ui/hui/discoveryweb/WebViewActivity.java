package im.uwrkaxlmjj.ui.hui.discoveryweb;

import android.graphics.Bitmap;
import android.os.Bundle;
import android.webkit.WebView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.just.agentweb.AgentWeb;
import com.just.agentweb.WebChromeClient;
import com.just.agentweb.WebViewClient;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WebViewActivity extends AppCompatActivity {
    private AgentWeb agentWebView;
    private ConstraintLayout main;
    private WebViewClient mWebViewClient = new WebViewClient() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.WebViewActivity.1
        @Override // com.just.agentweb.WebViewClientDelegate, android.webkit.WebViewClient
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
        }
    };
    private WebChromeClient mWebChromeClient = new WebChromeClient() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.WebViewActivity.2
        @Override // com.just.agentweb.WebChromeClientDelegate, android.webkit.WebChromeClient
        public void onProgressChanged(WebView view, int newProgress) {
        }
    };

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_web_view);
        this.main = (ConstraintLayout) findViewById(R.attr.main);
        this.agentWebView = AgentWeb.with(this).setAgentWebParent(this.main, new ConstraintLayout.LayoutParams(-1, -1)).useDefaultIndicator().createAgentWeb().ready().go("https://20.187.161.195:31035/mobile/#/login");
    }
}
