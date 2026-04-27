package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import androidx.recyclerview.widget.LinearLayoutManager;
import butterknife.BindView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.WhoCanWatchAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcActivity;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WhoCanWatchActivity extends CommFcActivity {
    private WhoCanWatchAdapter adapter;

    @BindView(R.attr.rv)
    RecyclerListView rv;

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected int getLayoutRes() {
        return R.layout.activity_fc_who_can_watch;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initView() {
        useButterKnife();
        this.rv.setLayoutManager(new LinearLayoutManager(getParentActivity()));
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initData() {
    }
}
