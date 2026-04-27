package im.uwrkaxlmjj.ui.hui.packet;

import android.content.Context;
import android.text.Html;
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
import im.uwrkaxlmjj.messenger.utils.TextTool;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketResponse;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.math.BigDecimal;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedpktDetailReceiverActivity extends BaseFragment {
    private RedpacketResponse bean;

    @BindView(R.attr.biv_rpk_avatar)
    BackupImageView bivRpkAvatar;

    @BindView(R.attr.llUserLayout)
    LinearLayout llUserLayout;
    private MryTextView rptView;
    private final int rpt_record = 101;
    private TLRPC.User sender;

    @BindView(R.attr.tv_rpk_amount)
    TextView tvRpkAmount;

    @BindView(R.attr.tv_rpk_desc)
    TextView tvRpkDesc;

    @BindView(R.attr.tv_rpk_greet)
    TextView tvRpkGreet;

    @BindView(R.attr.tv_rpk_name)
    TextView tvRpkName;

    public void setBean(RedpacketResponse bean) {
        this.bean = bean;
        this.sender = getMessagesController().getUser(Integer.valueOf(Integer.parseInt(bean.getRed().getInitiatorUserId())));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_redpkg_receiver_state_layout, (ViewGroup) null, false);
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
        this.actionBar.getBackButton().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktDetailReceiverActivity$DoiVBiXcCviYTWqqUvWTC44kPs4
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$0$RedpktDetailReceiverActivity(view);
            }
        });
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.packet.RedpktDetailReceiverActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    RedpktDetailReceiverActivity.this.finishFragment();
                } else if (id == 101) {
                    RedpktRecordsActivity recordsActivity = new RedpktRecordsActivity();
                    RedpktDetailReceiverActivity.this.presentFragment(recordsActivity);
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        MryTextView mryTextView = new MryTextView(getParentActivity());
        this.rptView = mryTextView;
        mryTextView.setMryText(R.string.RedPacketRecords);
        this.rptView.setTextSize(1, 14.0f);
        this.rptView.setBold();
        this.rptView.setTextColor(-1);
        this.rptView.setGravity(17);
        menu.addItemView(101, this.rptView);
    }

    public /* synthetic */ void lambda$initActionBar$0$RedpktDetailReceiverActivity(View v) {
        finishFragment();
    }

    private void initViews() {
        if (this.sender != null) {
            AvatarDrawable avatarDrawable = new AvatarDrawable();
            avatarDrawable.setTextSize(AndroidUtilities.dp(16.0f));
            avatarDrawable.setInfo(this.sender);
            this.bivRpkAvatar.setRoundRadius(AndroidUtilities.dp(7.0f));
            this.bivRpkAvatar.getImageReceiver().setCurrentAccount(this.currentAccount);
            this.bivRpkAvatar.setImage(ImageLocation.getForUser(this.sender, false), "50_50", avatarDrawable, this.sender);
            this.tvRpkName.setText(UserObject.getName(this.sender));
        }
        RedpacketResponse redpacketResponse = this.bean;
        if (redpacketResponse != null) {
            if (redpacketResponse.getRed().getRemarks() == null || TextUtils.isEmpty(this.bean.getRed().getRemarks())) {
                this.tvRpkGreet.setText(LocaleController.getString(R.string.redpacket_greetings_tip));
            } else {
                this.tvRpkGreet.setText(this.bean.getRed().getRemarks());
            }
            String transTotal = "";
            if (this.bean.getRed().getTotalFee() != null && !TextUtils.isEmpty(this.bean.getRed().getTotalFee())) {
                BigDecimal bitTotal = new BigDecimal(this.bean.getRed().getTotalFee());
                transTotal = DataTools.format2Decimals(bitTotal.divide(new BigDecimal("100")).toString());
            }
            TextTool.Builder builder = TextTool.getBuilder("");
            builder.append(transTotal).setForegroundColor(-3416);
            builder.append(LocaleController.getString(R.string.UnitCNY));
            builder.setProportion(0.5f).into(this.tvRpkAmount);
            this.tvRpkDesc.setText(Html.fromHtml(LocaleController.getString(R.string.ViewWalletBalance)));
        }
    }
}
