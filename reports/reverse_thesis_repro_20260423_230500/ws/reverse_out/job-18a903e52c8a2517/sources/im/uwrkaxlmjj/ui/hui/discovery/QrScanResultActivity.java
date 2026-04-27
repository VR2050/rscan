package im.uwrkaxlmjj.ui.hui.discovery;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class QrScanResultActivity extends BaseFragment {
    private Context mContext;
    private TextView mTvResult;
    private String text;

    public QrScanResultActivity(String text) {
        this.text = text;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_qr_scan_result, (ViewGroup) null);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initView();
        initActionBar();
        return this.fragmentView;
    }

    private void initView() {
        ScrollView scrollView = (ScrollView) this.fragmentView.findViewById(R.attr.scroll_view);
        this.mTvResult = (TextView) this.fragmentView.findViewById(R.attr.tv_result);
        scrollView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.mTvResult.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.mTvResult.setText(this.text);
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString("QrScanResult", R.string.QrScanResult));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addItem(1, LocaleController.getString("Copy", R.string.Copy));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.discovery.QrScanResultActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    QrScanResultActivity.this.finishFragment();
                } else if (id == 1) {
                    QrScanResultActivity.this.copy();
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void copy() {
        String result = this.mTvResult.getText().toString().trim();
        ClipboardManager clipboard = (ClipboardManager) this.mContext.getSystemService("clipboard");
        ClipData clip = ClipData.newPlainText("result", result);
        clipboard.setPrimaryClip(clip);
        ToastUtils.show(R.string.CopySuccess);
    }
}
