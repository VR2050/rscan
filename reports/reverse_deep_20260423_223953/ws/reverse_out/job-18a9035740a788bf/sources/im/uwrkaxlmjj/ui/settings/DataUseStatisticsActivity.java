package im.uwrkaxlmjj.ui.settings;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.StatsController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class DataUseStatisticsActivity extends BaseFragment implements View.OnClickListener {
    private ImageView mIvBack;
    private RelativeLayout mRlBack;
    private RelativeLayout mRlReset;
    private TextView mtvCAllSent;
    private TextView mtvCallReceive;
    private TextView mtvCurrent;
    private TextView mtvFileReceive;
    private TextView mtvFileSent;
    private TextView mtvMobile;
    private TextView mtvMsgReceive;
    private TextView mtvMsgSent;
    private TextView mtvPhotoReceive;
    private TextView mtvPhotoSent;
    private TextView mtvVideoReceive;
    private TextView mtvVideoSent;
    private TextView mtvWifi;
    private LinearLayout tabContainer;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setAddToContainer(false);
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_setting_data_use_statistics, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initTitleBar();
        initView(context);
        return this.fragmentView;
    }

    private void initTitleBar() {
        FrameLayout flTitleBarContainer = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_title_bar_container);
        flTitleBarContainer.setBackground(this.defaultActionBarBackgroundDrawable);
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) flTitleBarContainer.getLayoutParams();
        layoutParams.height = ActionBar.getCurrentActionBarHeight() + AndroidUtilities.statusBarHeight;
        flTitleBarContainer.setLayoutParams(layoutParams);
        flTitleBarContainer.setPadding(0, AndroidUtilities.statusBarHeight, 0, 0);
        this.tabContainer = (LinearLayout) this.fragmentView.findViewById(R.attr.tabContainer);
        this.mRlBack = (RelativeLayout) this.fragmentView.findViewById(R.attr.rl_back);
        ImageView imageView = (ImageView) this.fragmentView.findViewById(R.attr.iv_back);
        this.mIvBack = imageView;
        imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_actionBarDefaultIcon), PorterDuff.Mode.MULTIPLY));
        this.mIvBack.setBackground(Theme.createSelectorDrawable(Theme.getColor(Theme.key_actionBarDefaultSelector)));
        this.mtvMobile = (TextView) this.fragmentView.findViewById(R.attr.tv_moblie);
        this.mtvWifi = (TextView) this.fragmentView.findViewById(R.attr.tv_wifi);
        this.mtvCurrent = this.mtvMobile;
    }

    private void initView(Context context) {
        this.mtvMsgSent = (TextView) this.fragmentView.findViewById(R.attr.tv_msg_sent);
        this.mtvMsgReceive = (TextView) this.fragmentView.findViewById(R.attr.tv_msg_receive);
        this.mtvPhotoSent = (TextView) this.fragmentView.findViewById(R.attr.tv_photo_sent);
        this.mtvPhotoReceive = (TextView) this.fragmentView.findViewById(R.attr.tv_photo_receive);
        this.mtvVideoSent = (TextView) this.fragmentView.findViewById(R.attr.tv_video_sent);
        this.mtvVideoReceive = (TextView) this.fragmentView.findViewById(R.attr.tv_video_receive);
        this.mtvFileSent = (TextView) this.fragmentView.findViewById(R.attr.tv_file_sent);
        this.mtvFileReceive = (TextView) this.fragmentView.findViewById(R.attr.tv_file_receive);
        this.mtvCAllSent = (TextView) this.fragmentView.findViewById(R.attr.tv_call_sent);
        this.mtvCallReceive = (TextView) this.fragmentView.findViewById(R.attr.tv_call_receive);
        this.mRlReset = (RelativeLayout) this.fragmentView.findViewById(R.attr.rl_reset_download_file);
        Drawable topRroundDrawable = Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite));
        Drawable bottomRoundDrawable = Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite));
        this.fragmentView.findViewById(R.attr.rl_store_number).setBackground(topRroundDrawable);
        this.fragmentView.findViewById(R.attr.rl_network_number).setBackground(bottomRoundDrawable);
        this.fragmentView.findViewById(R.attr.rl_photo_send).setBackground(topRroundDrawable);
        this.fragmentView.findViewById(R.attr.rl_photo_recv).setBackground(bottomRoundDrawable);
        this.fragmentView.findViewById(R.attr.rl_video_send).setBackground(topRroundDrawable);
        this.fragmentView.findViewById(R.attr.rl_video_recv).setBackground(bottomRoundDrawable);
        this.fragmentView.findViewById(R.attr.rl_file_send).setBackground(topRroundDrawable);
        this.fragmentView.findViewById(R.attr.rl_file_recv).setBackground(bottomRoundDrawable);
        this.fragmentView.findViewById(R.attr.rl_call_send).setBackground(topRroundDrawable);
        this.fragmentView.findViewById(R.attr.rl_call_recv).setBackground(bottomRoundDrawable);
        this.fragmentView.findViewById(R.attr.rl_reset_download_file).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        initListener();
        changeTabState(this.mtvCurrent);
    }

    private void initListener() {
        this.mtvMobile.setOnClickListener(this);
        this.mtvWifi.setOnClickListener(this);
        this.mRlBack.setOnClickListener(this);
        this.mRlReset.setOnClickListener(this);
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View v) {
        switch (v.getId()) {
            case R.attr.rl_back /* 2131297143 */:
                finishFragment();
                break;
            case R.attr.rl_reset_download_file /* 2131297197 */:
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                builder.setTitle(LocaleController.getString("ResetStatisticsAlertTitle", R.string.ResetStatisticsAlertTitle));
                builder.setMessage(LocaleController.getString("ResetStatisticsAlert", R.string.ResetStatisticsAlert));
                builder.setPositiveButton(LocaleController.getString("Reset", R.string.Reset), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$DataUseStatisticsActivity$JpbG7TG1rnE9zGc39CDZBhoJddo
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onClick$0$DataUseStatisticsActivity(dialogInterface, i);
                    }
                });
                builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                AlertDialog dialog = builder.create();
                showDialog(dialog);
                TextView button = (TextView) dialog.getButton(-1);
                if (button != null) {
                    button.setTextColor(Theme.getColor(Theme.key_dialogTextRed2));
                }
                break;
            case R.attr.tv_moblie /* 2131297774 */:
                if (this.mtvCurrent.getId() != v.getId()) {
                    changeTabState(v);
                    this.mtvCurrent = this.mtvMobile;
                    initState();
                }
                break;
            case R.attr.tv_wifi /* 2131297867 */:
                if (this.mtvCurrent.getId() != v.getId()) {
                    changeTabState(v);
                    this.mtvCurrent = this.mtvWifi;
                    initState();
                }
                break;
        }
    }

    public /* synthetic */ void lambda$onClick$0$DataUseStatisticsActivity(DialogInterface dialogInterface, int i) {
        int type = 0;
        if (this.mtvCurrent == this.mtvWifi) {
            type = 1;
        }
        StatsController.getInstance(this.currentAccount).resetStats(type);
        initState();
    }

    private void changeTabState(View view) {
        if (view.getId() == this.mtvMobile.getId()) {
            if (this.tabContainer.getBackground() != null) {
                this.tabContainer.getBackground().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText), PorterDuff.Mode.SRC_IN));
            }
            this.mtvMobile.setTextColor(-1);
            this.mtvMobile.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), 0.0f, AndroidUtilities.dp(5.0f), 0.0f, Theme.getColor(Theme.key_windowBackgroundWhiteBlueText)));
            this.mtvWifi.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
            this.mtvWifi.setBackground(Theme.createRoundRectDrawable(0.0f, AndroidUtilities.dp(5.0f), 0.0f, AndroidUtilities.dp(5.0f), 0));
            return;
        }
        if (this.tabContainer.getBackground() != null) {
            this.tabContainer.getBackground().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText), PorterDuff.Mode.SRC_IN));
        }
        this.mtvWifi.setTextColor(-1);
        this.mtvWifi.setBackground(Theme.createRoundRectDrawable(0.0f, AndroidUtilities.dp(5.0f), 0.0f, AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhiteBlueText)));
        this.mtvMobile.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
        this.mtvMobile.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), 0.0f, AndroidUtilities.dp(5.0f), 0.0f, 0));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        initState();
    }

    private void initState() {
        int type = 0;
        if (this.mtvCurrent == this.mtvWifi) {
            type = 1;
        }
        this.mtvMsgSent.setText(AndroidUtilities.formatFileSize(StatsController.getInstance(this.currentAccount).getSentBytesCount(type, 1)));
        this.mtvMsgReceive.setText(AndroidUtilities.formatFileSize(StatsController.getInstance(this.currentAccount).getReceivedBytesCount(type, 1)));
        this.mtvPhotoSent.setText(AndroidUtilities.formatFileSize(StatsController.getInstance(this.currentAccount).getSentBytesCount(type, 4)));
        this.mtvPhotoReceive.setText(AndroidUtilities.formatFileSize(StatsController.getInstance(this.currentAccount).getReceivedBytesCount(type, 4)));
        this.mtvVideoSent.setText(AndroidUtilities.formatFileSize(StatsController.getInstance(this.currentAccount).getSentBytesCount(type, 2)));
        this.mtvVideoReceive.setText(AndroidUtilities.formatFileSize(StatsController.getInstance(this.currentAccount).getReceivedBytesCount(type, 2)));
        this.mtvFileSent.setText(AndroidUtilities.formatFileSize(StatsController.getInstance(this.currentAccount).getSentBytesCount(type, 5)));
        this.mtvFileReceive.setText(AndroidUtilities.formatFileSize(StatsController.getInstance(this.currentAccount).getReceivedBytesCount(type, 5)));
        this.mtvCAllSent.setText(AndroidUtilities.formatFileSize(StatsController.getInstance(this.currentAccount).getSentBytesCount(type, 0)));
        this.mtvCallReceive.setText(AndroidUtilities.formatFileSize(StatsController.getInstance(this.currentAccount).getReceivedBytesCount(type, 0)));
    }
}
