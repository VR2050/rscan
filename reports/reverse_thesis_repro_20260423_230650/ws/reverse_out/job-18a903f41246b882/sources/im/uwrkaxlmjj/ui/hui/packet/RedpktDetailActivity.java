package im.uwrkaxlmjj.ui.hui.packet;

import android.content.Context;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import butterknife.BindView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.utils.DataTools;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketResponse;
import java.math.BigDecimal;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedpktDetailActivity extends BaseFragment {
    private RedpacketResponse bean;

    @BindView(R.attr.biv_receiver_avatar)
    BackupImageView bivReceiverAvatar;

    @BindView(R.attr.fl_rpk_record_layout)
    FrameLayout flRpkRecordLayout;

    @BindView(R.attr.ivRptAvatar)
    BackupImageView ivRptAvatar;

    @BindView(R.attr.llUserLayout)
    LinearLayout llUserLayout;
    private TextView rptView;
    private final int rpt_record = 101;
    private TLRPC.User sender;

    @BindView(R.attr.tv_rpk_amount)
    TextView tvRpkAmount;

    @BindView(R.attr.tv_rpk_back_desc)
    TextView tvRpkBackDesc;

    @BindView(R.attr.tv_rpk_name)
    TextView tvRpkName;

    @BindView(R.attr.tv_rpk_receive_time)
    TextView tvRpkReceiveTime;

    @BindView(R.attr.tvRptGreet)
    TextView tvRptGreet;

    @BindView(R.attr.tvRptName)
    TextView tvRptName;

    @BindView(R.attr.tvRptState)
    TextView tvRptState;

    public void setBean(RedpacketResponse bean) {
        this.bean = bean;
        this.sender = getMessagesController().getUser(Integer.valueOf(Integer.parseInt(bean.getRed().getInitiatorUserId())));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_redpkg_state_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(-328966);
        useButterKnife();
        initActionBar();
        initViews();
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setAddToContainer(false);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        frameLayout.addView(this.actionBar);
        this.actionBar.setTitle(LocaleController.getString(R.string.DetailsOfRedPackets));
        this.actionBar.setTitleColor(-1);
        this.actionBar.setItemsColor(-1, false);
        this.actionBar.setBackgroundColor(0);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setCastShadows(false);
        this.actionBar.setBackButtonImage(R.id.ic_back_white);
        this.actionBar.getBackButton().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktDetailActivity$-l4CDJ1q6fWsVTesh1SjAT7yFk4
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$0$RedpktDetailActivity(view);
            }
        });
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.packet.RedpktDetailActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    RedpktDetailActivity.this.finishFragment();
                } else if (id == 101) {
                    RedpktRecordsActivity recordsActivity = new RedpktRecordsActivity();
                    RedpktDetailActivity.this.presentFragment(recordsActivity);
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        TextView textView = new TextView(getParentActivity());
        this.rptView = textView;
        textView.setText(LocaleController.getString(R.string.RedPacketRecords));
        this.rptView.setTextSize(1, 14.0f);
        this.rptView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.rptView.setTextColor(-1);
        this.rptView.setGravity(17);
        menu.addItemView(101, this.rptView);
    }

    public /* synthetic */ void lambda$initActionBar$0$RedpktDetailActivity(View v) {
        finishFragment();
    }

    private void initViews() {
        AvatarDrawable avatarDrawable = new AvatarDrawable();
        avatarDrawable.setTextSize(AndroidUtilities.dp(16.0f));
        avatarDrawable.setInfo(this.sender);
        this.ivRptAvatar.setRoundRadius(AndroidUtilities.dp(7.5f));
        this.ivRptAvatar.getImageReceiver().setCurrentAccount(this.currentAccount);
        this.ivRptAvatar.setImage(ImageLocation.getForUser(this.sender, false), "50_50", avatarDrawable, this.sender);
        this.tvRptName.setText(UserObject.getName(this.sender));
        this.tvRptState.setVisibility(0);
        this.tvRpkBackDesc.setText(LocaleController.getString(R.string.RedPacketsWillReturnWhenNotReceivedIn24Hours));
        RedpacketResponse redpacketResponse = this.bean;
        if (redpacketResponse != null) {
            if (redpacketResponse.getRed().getRemarks() == null || TextUtils.isEmpty(this.bean.getRed().getRemarks())) {
                this.tvRptGreet.setText(LocaleController.getString(R.string.redpacket_greetings_tip));
            } else {
                this.tvRptGreet.setText(this.bean.getRed().getRemarks());
            }
            String transTotal = "";
            if (this.bean.getRed().getTotalFee() != null && !TextUtils.isEmpty(this.bean.getRed().getTotalFee())) {
                BigDecimal bitTotal = new BigDecimal(this.bean.getRed().getTotalFee());
                transTotal = DataTools.format2Decimals(bitTotal.multiply(new BigDecimal("0.01")).toString());
            }
            if (this.bean.getRed().getStatus() != null && !TextUtils.isEmpty(this.bean.getRed().getStatus())) {
                if ("0".equals(this.bean.getRed().getStatus())) {
                    this.tvRptState.setText(String.format("1" + LocaleController.getString(R.string.redpacket_each) + LocaleController.getString(R.string.RedPacket) + LocaleController.getString(R.string.TotalSingleWords) + "%s" + LocaleController.getString(R.string.UnitCNY) + LocaleController.getString(R.string.Comma) + "%s", transTotal, LocaleController.getString(R.string.WaitToReceived)));
                    return;
                }
                if ("1".equals(this.bean.getRed().getStatus())) {
                    this.tvRptState.setText(String.format("" + LocaleController.getString(R.string.AlreadyReceive) + "1/1" + LocaleController.getString(R.string.redpacket_each) + LocaleController.getString(R.string.Comma) + LocaleController.getString(R.string.TotalSingleWords) + "%s" + LocaleController.getString(R.string.UnitCNY) + "/%s" + LocaleController.getString(R.string.UnitCNY), transTotal, transTotal));
                    this.flRpkRecordLayout.setVisibility(0);
                    TLRPC.User receiver = getMessagesController().getUser(Integer.valueOf(Integer.parseInt(this.bean.getRed().getRecipientUserId())));
                    AvatarDrawable recvAvatar = new AvatarDrawable();
                    recvAvatar.setTextSize(AndroidUtilities.dp(16.0f));
                    recvAvatar.setInfo(receiver);
                    this.bivReceiverAvatar.setRoundRadius(AndroidUtilities.dp(32.0f));
                    this.bivReceiverAvatar.getImageReceiver().setCurrentAccount(this.currentAccount);
                    this.bivReceiverAvatar.setImage(ImageLocation.getForUser(receiver, false), "50_50", recvAvatar, receiver);
                    this.tvRpkName.setText(receiver.first_name);
                    this.tvRpkAmount.setText(transTotal);
                    if (this.bean.getRed() != null && this.bean.getRed().getCompleteTime() != null) {
                        this.tvRpkReceiveTime.setText(this.bean.getRed().getCompleteTimeFormat());
                    }
                    this.tvRpkBackDesc.setVisibility(8);
                    return;
                }
                this.tvRptState.setText(String.format("" + LocaleController.getString(R.string.RedpacketHadExpired) + LocaleController.getString(R.string.FullStop) + LocaleController.getString(R.string.AlreadyReceive) + "0/1" + LocaleController.getString(R.string.redpacket_each) + LocaleController.getString(R.string.Comma) + LocaleController.getString(R.string.TotalSingleWords) + "0.00/%s" + LocaleController.getString(R.string.UnitCNY), transTotal));
            }
        }
    }
}
