package im.uwrkaxlmjj.ui.hui.mine;

import android.content.Context;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import butterknife.BindView;
import butterknife.OnClick;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FeedbackActivity extends BaseFragment {

    @BindView(R.attr.btnFeedSubmit)
    Button btnFeedSubmit;

    @BindView(R.attr.etFeedDescText)
    EditText etFeedDescText;

    @BindView(R.attr.mryFeedTitle)
    MryTextView mryFeedTitle;

    @BindView(R.attr.tvFeedPromt)
    TextView tvFeedPromt;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_feed_back_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        initActionBar();
        initView();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle("反馈问题或建议");
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.mine.FeedbackActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    FeedbackActivity.this.finishFragment();
                }
            }
        });
    }

    private void initView() {
        this.mryFeedTitle.setBold();
        this.mryFeedTitle.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.mryFeedTitle.setText("问题或建议（不少于5个字）");
        this.tvFeedPromt.setBackgroundColor(-570319);
        this.tvFeedPromt.setVisibility(8);
        this.etFeedDescText.setHint("请输入描述性文字（必填）");
        this.etFeedDescText.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
        this.etFeedDescText.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(7.5f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.btnFeedSubmit.setText("提交");
        this.btnFeedSubmit.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.btnFeedSubmit.setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(7.5f), Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton)));
    }

    private void submitInfomation() {
        String info = this.etFeedDescText.getText().toString().trim();
        if (TextUtils.isEmpty(info)) {
            this.tvFeedPromt.setText("请填写描述文字");
            this.tvFeedPromt.setVisibility(0);
            this.mryFeedTitle.setVisibility(8);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$FeedbackActivity$3kvvGPw_VX8u1ymoqHacD79oyh0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$submitInfomation$0$FeedbackActivity();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            return;
        }
        if (info.length() < 5) {
            this.tvFeedPromt.setText("请填写不低于5个字的描述");
            this.tvFeedPromt.setVisibility(0);
            this.mryFeedTitle.setVisibility(8);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.mine.-$$Lambda$FeedbackActivity$MhsJia-XEpEJiwfmPtT_JsLryq0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$submitInfomation$1$FeedbackActivity();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            return;
        }
        this.tvFeedPromt.setVisibility(8);
        this.mryFeedTitle.setVisibility(0);
    }

    public /* synthetic */ void lambda$submitInfomation$0$FeedbackActivity() {
        this.tvFeedPromt.setVisibility(8);
        this.mryFeedTitle.setVisibility(0);
    }

    public /* synthetic */ void lambda$submitInfomation$1$FeedbackActivity() {
        this.tvFeedPromt.setVisibility(8);
        this.mryFeedTitle.setVisibility(0);
    }

    @OnClick({R.attr.btnFeedSubmit})
    public void onViewClicked() {
        submitInfomation();
    }
}
