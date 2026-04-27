package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.utils.number.NumberUtil;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class IpChangeActivity extends BaseFragment {
    private final int done = 1;
    private TextView doneTextBtn;
    private TextView tvChangeIp;
    private TextView tvChangePort;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_change_ip_layout, (ViewGroup) null, false);
        useButterKnife();
        initActionBar();
        initView();
        return this.fragmentView;
    }

    private void initView() {
        this.tvChangeIp = (TextView) this.fragmentView.findViewById(R.attr.et_ip_text);
        this.tvChangePort = (TextView) this.fragmentView.findViewById(R.attr.et_port_text);
    }

    private void initActionBar() {
        this.actionBar.setTitle("IP切换");
        this.actionBar.setBackButtonImage(R.id.ic_back);
        ActionBarMenu menu = this.actionBar.createMenu();
        TextView textView = new TextView(getParentActivity());
        this.doneTextBtn = textView;
        textView.setText("完成");
        this.doneTextBtn.setTextSize(1, 14.0f);
        this.doneTextBtn.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.doneTextBtn.setGravity(16);
        menu.addItemView(1, this.doneTextBtn);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.IpChangeActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    IpChangeActivity.this.finishFragment();
                } else if (id == 1) {
                    IpChangeActivity.this.changeIp();
                    IpChangeActivity.this.finishFragment();
                }
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void changeIp() {
        String ip = this.tvChangeIp.getText().toString();
        String port = this.tvChangePort.getText().toString();
        if (!TextUtils.isEmpty(ip) && !TextUtils.isEmpty(port) && NumberUtil.isNumber(port)) {
            ConnectionsManager.getInstance(UserConfig.selectedAccount).applyDatacenterAddress(2, ip, Integer.parseInt(port));
            ConnectionsManager.getInstance(UserConfig.selectedAccount).resumeNetworkMaybe();
        } else {
            ToastUtils.show((CharSequence) "请检查输入的地址和端口");
        }
    }
}
