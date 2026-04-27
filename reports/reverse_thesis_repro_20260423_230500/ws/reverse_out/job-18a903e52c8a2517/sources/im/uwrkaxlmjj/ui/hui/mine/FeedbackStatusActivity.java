package im.uwrkaxlmjj.ui.hui.mine;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import butterknife.BindView;
import butterknife.OnClick;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FeedbackStatusActivity extends BaseFragment {

    @BindView(R.attr.btnFinish)
    Button btnFinish;

    @BindView(R.attr.ivFeedStatusImg)
    ImageView ivFeedStatusImg;

    @BindView(R.attr.mryFeedDescText)
    MryTextView mryFeedDescText;

    @BindView(R.attr.mryFeedStatusText)
    MryTextView mryFeedStatusText;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_feed_back_success_layout, (ViewGroup) null, false);
        useButterKnife();
        initActionBar();
        initView();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle("反馈问题或建议");
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.mine.FeedbackStatusActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    FeedbackStatusActivity.this.finishFragment();
                }
            }
        });
    }

    private void initView() {
    }

    @OnClick({R.attr.btnFinish})
    public void onViewClicked() {
        finishFragment();
    }
}
