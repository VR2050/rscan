package im.uwrkaxlmjj.ui.hui.packet;

import android.content.Context;
import android.text.Layout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.method.LinkMovementMethod;
import android.text.style.ClickableSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.BindView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.utils.DataTools;
import im.uwrkaxlmjj.messenger.utils.TextTool;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketBean;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketDetailRecord;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketDetailResponse;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.math.BigDecimal;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedpktGroupStateActivity extends BaseFragment {
    private RedpacketDetailResponse bean;
    private boolean isRandom;
    private MessageObject messageObject;

    @BindView(R.attr.rcy_rpk_history)
    RecyclerListView rcyRpkHistory;
    private ArrayList<RedpacketDetailRecord> records;
    private MryTextView rptView;
    private TLRPC.User targetUser;

    @BindView(R.attr.tv_rpk_back_desc)
    TextView tvRpkBackDesc;
    private final int rpt_record = 101;
    private int headerRow = -1;
    private int headerSessionRow = -1;
    private int recordStart = -1;
    private int recordEnd = -1;
    private int rowCount = 0;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_redpkg_group_state_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(-328966);
        useButterKnife();
        initActionBar();
        updateRows();
        initViews();
        return this.fragmentView;
    }

    public void setBean(RedpacketDetailResponse bean) {
        this.bean = bean;
        this.records = bean.getRecord();
        if (bean.getRed() != null && bean.getRed().getGrantType() != null) {
            this.isRandom = "1".equals(bean.getRed().getGrantType());
        }
    }

    public void setMessageObject(MessageObject messageObject) {
        this.messageObject = messageObject;
    }

    public void setTargetUser(TLRPC.User targetUser) {
        this.targetUser = targetUser;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString(R.string.DetailsOfRedPackets));
        this.actionBar.setTitleColor(-1);
        this.actionBar.setItemsColor(-1, false);
        this.actionBar.setBackgroundColor(-2737326);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setBackButtonImage(R.id.ic_back_white);
        this.actionBar.getBackButton().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupStateActivity$Hb7-GfNRAUshc2cpIysO3p_OWuo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$0$RedpktGroupStateActivity(view);
            }
        });
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.packet.RedpktGroupStateActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    RedpktGroupStateActivity.this.finishFragment();
                } else if (id == 101) {
                    RedpktRecordsActivity recordsActivity = new RedpktRecordsActivity();
                    RedpktGroupStateActivity.this.presentFragment(recordsActivity);
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

    public /* synthetic */ void lambda$initActionBar$0$RedpktGroupStateActivity(View v) {
        finishFragment();
    }

    private void updateRows() {
        int i = this.rowCount;
        int i2 = i + 1;
        this.rowCount = i2;
        this.headerRow = i;
        this.rowCount = i2 + 1;
        this.headerSessionRow = i2;
        ArrayList<RedpacketDetailRecord> arrayList = this.records;
        if (arrayList != null && arrayList.size() > 0) {
            int i3 = this.rowCount;
            this.rowCount = i3 + 1;
            this.recordStart = i3;
            this.recordEnd = (i3 + this.records.size()) - 1;
            this.rowCount += this.records.size() - 1;
        }
    }

    private void initViews() {
        this.rcyRpkHistory.setLayoutManager(new LinearLayoutManager(getParentActivity()));
        this.rcyRpkHistory.setAdapter(new ListAdapter(getParentActivity()));
        this.tvRpkBackDesc.setText(LocaleController.getString(R.string.RedPacketsWillReturnWhenNotReceivedIn24Hours));
        RedpacketDetailResponse redpacketDetailResponse = this.bean;
        if (redpacketDetailResponse != null && redpacketDetailResponse.getRecord() != null && this.bean.getRed() != null) {
            this.tvRpkBackDesc.setVisibility(this.bean.getRed().getNumber() == this.bean.getRecord().size() ? 8 : 0);
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context mContext) {
            this.mContext = mContext;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int itemViewType = holder.getItemViewType();
            return itemViewType == 2;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = LayoutInflater.from(this.mContext).inflate(R.layout.item_redpkg_state_header_layout, (ViewGroup) null);
                view.setBackgroundColor(-1);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            } else if (viewType != 1) {
                view = LayoutInflater.from(this.mContext).inflate(R.layout.item_red_packet_records, (ViewGroup) null);
                view.setBackgroundColor(-1);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(72.0f)));
            } else {
                view = new TextView(this.mContext);
                view.setBackgroundColor(-328966);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(48.0f)));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != RedpktGroupStateActivity.this.headerRow) {
                if (position == RedpktGroupStateActivity.this.headerSessionRow) {
                    return 1;
                }
                return 2;
            }
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            CharSequence charSequence;
            if (position == 0) {
                BackupImageView ivRptAvatar = (BackupImageView) holder.itemView.findViewById(R.attr.ivRptAvatar);
                TextView tvRptName = (TextView) holder.itemView.findViewById(R.attr.tvRptName);
                TextView tvRptGreet = (TextView) holder.itemView.findViewById(R.attr.tvRptGreet);
                TextView tvReceivedCount = (TextView) holder.itemView.findViewById(R.attr.tvReceivedCount);
                TextView tvReceivedPromt = (TextView) holder.itemView.findViewById(R.attr.tvReceivedPromt);
                TLRPC.User sender = RedpktGroupStateActivity.this.getMessagesController().getUser(Integer.valueOf(Integer.parseInt(RedpktGroupStateActivity.this.bean.getRed().getInitiatorUserId())));
                if (sender != null) {
                    AvatarDrawable avatarDrawable = new AvatarDrawable();
                    avatarDrawable.setTextSize(AndroidUtilities.dp(16.0f));
                    avatarDrawable.setInfo(sender);
                    ivRptAvatar.setRoundRadius(AndroidUtilities.dp(32.0f));
                    ivRptAvatar.getImageReceiver().setCurrentAccount(RedpktGroupStateActivity.this.currentAccount);
                    ivRptAvatar.setImage(ImageLocation.getForUser(sender, false), "50_50", avatarDrawable, sender);
                    tvRptName.setText(sender.first_name);
                }
                if (RedpktGroupStateActivity.this.bean.getRed().getRemarks() != null && !TextUtils.isEmpty(RedpktGroupStateActivity.this.bean.getRed().getRemarks())) {
                    tvRptGreet.setText(RedpktGroupStateActivity.this.bean.getRed().getRemarks());
                    tvRptGreet.setTextColor(-1);
                } else {
                    tvRptGreet.setText(LocaleController.getString(R.string.redpacket_greetings_tip));
                    tvRptGreet.setTextColor(-1);
                }
                if (RedpktGroupStateActivity.this.bean.getRed().getIsReceived() == 0) {
                    tvReceivedCount.setVisibility(8);
                    tvReceivedPromt.setVisibility(8);
                    return;
                }
                tvReceivedCount.setVisibility(0);
                tvReceivedPromt.setVisibility(0);
                BigDecimal bigDecimal = new BigDecimal(String.valueOf(RedpktGroupStateActivity.this.bean.getRed().getMoney()));
                TextTool.Builder textBuilder = TextTool.getBuilder("").setContext(RedpktGroupStateActivity.this.getParentActivity()).setBold().setAlign(Layout.Alignment.ALIGN_CENTER).append(DataTools.format2Decimals(bigDecimal.divide(new BigDecimal("100")).toString())).setForegroundColor(-2737326).setProportion(2.0f);
                textBuilder.append(LocaleController.getString(R.string.UnitCNY));
                textBuilder.into(tvReceivedCount);
                ClickableSpan jumpToWallet = new ClickableSpan() { // from class: im.uwrkaxlmjj.ui.hui.packet.RedpktGroupStateActivity.ListAdapter.1
                    @Override // android.text.style.ClickableSpan
                    public void onClick(View widget) {
                    }

                    @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
                    public void updateDrawState(TextPaint ds) {
                        ds.setColor(-16745729);
                        ds.setUnderlineText(false);
                    }
                };
                tvReceivedPromt.setMovementMethod(LinkMovementMethod.getInstance());
                TextTool.getBuilder("").setContext(RedpktGroupStateActivity.this.getParentActivity()).setBold().setAlign(Layout.Alignment.ALIGN_CENTER).append(LocaleController.getString(R.string.SaveToBalanceAndDetails)).setForegroundColor(-6710887).append(LocaleController.getString(R.string.Wallet)).setForegroundColor(-14250753).setClickSpan(jumpToWallet).append(LocaleController.getString(R.string.TransferSeeIn)).setForegroundColor(-6710887).into(tvReceivedPromt);
                return;
            }
            if (position == 1) {
                TextView cell = (TextView) holder.itemView;
                cell.setPadding(AndroidUtilities.dp(16.0f), 0, AndroidUtilities.dp(16.0f), 0);
                cell.setGravity(16);
                BigDecimal total = new BigDecimal(RedpktGroupStateActivity.this.bean.getRed().getTotalFee());
                BigDecimal extal = new BigDecimal(RedpktGroupStateActivity.this.bean.getRed().getSurplusAmount());
                BigDecimal subtract = total.subtract(extal);
                int redType = Integer.parseInt(RedpktGroupStateActivity.this.bean.getRed().getRedType());
                int status = Integer.parseInt(RedpktGroupStateActivity.this.bean.getRed().getStatus());
                StringBuilder builder = new StringBuilder("");
                if (redType == 2) {
                    if (status == 0) {
                        builder.append("1");
                        builder.append(LocaleController.getString(R.string.redpacket_each));
                        builder.append(LocaleController.getString(R.string.RedPacket));
                        builder.append(LocaleController.getString(R.string.TotalSingleWords));
                        builder.append(DataTools.format2Decimals(total.divide(new BigDecimal("100")).toString()));
                        builder.append(LocaleController.getString(R.string.UnitCNY));
                        builder.append("，");
                        builder.append(LocaleController.getString(R.string.WaitToReceived));
                    } else if (status == 1) {
                        builder.append(LocaleController.getString(R.string.AlreadyReceive));
                        builder.append("1/1");
                        builder.append(LocaleController.getString(R.string.redpacket_each));
                        builder.append("，");
                        builder.append(LocaleController.getString(R.string.TotalSingleWords));
                        builder.append(DataTools.format2Decimals(total.divide(new BigDecimal("100")).toString()));
                        builder.append("/");
                        builder.append(DataTools.format2Decimals(total.divide(new BigDecimal("100")).toString()));
                        builder.append(LocaleController.getString(R.string.UnitCNY));
                    } else {
                        builder.append(LocaleController.getString(R.string.RedpacketHadExpired));
                        builder.append(LocaleController.getString(R.string.FullStop));
                        builder.append(LocaleController.getString(R.string.AlreadyReceive));
                        builder.append("0/1");
                        builder.append(LocaleController.getString(R.string.redpacket_each));
                        builder.append(LocaleController.getString(R.string.Comma));
                        builder.append(LocaleController.getString(R.string.TotalSingleWords));
                        builder.append("0.00/");
                        builder.append(DataTools.format2Decimals(total.divide(new BigDecimal("100")).toString()));
                        builder.append(LocaleController.getString(R.string.UnitCNY));
                    }
                } else if (status == 0) {
                    if (RedpktGroupStateActivity.this.bean.getRecord() == null || (RedpktGroupStateActivity.this.bean.getRecord() != null && RedpktGroupStateActivity.this.bean.getRecord().size() == 0)) {
                        builder.append(RedpktGroupStateActivity.this.bean.getRed().getNumber());
                        builder.append(LocaleController.getString(R.string.redpacket_each));
                        builder.append(LocaleController.getString(R.string.RedPacket));
                        builder.append(LocaleController.getString(R.string.TotalSingleWords));
                        builder.append(DataTools.format2Decimals(total.divide(new BigDecimal("100")).toString()));
                        builder.append(LocaleController.getString(R.string.UnitCNY));
                        builder.append(LocaleController.getString(R.string.Comma));
                        builder.append(LocaleController.getString(R.string.WaitToReceived));
                    } else {
                        builder.append(LocaleController.getString(R.string.AlreadyReceive));
                        builder.append(RedpktGroupStateActivity.this.bean.getRed().getNumber() - RedpktGroupStateActivity.this.bean.getRed().getSurplusNumber());
                        builder.append("/");
                        builder.append(RedpktGroupStateActivity.this.bean.getRed().getNumber());
                        builder.append(LocaleController.getString(R.string.TotalSingleWords));
                        builder.append(DataTools.format2Decimals(subtract.divide(new BigDecimal("100")).toString()));
                        builder.append("/");
                        builder.append(DataTools.format2Decimals(total.divide(new BigDecimal("100")).toString()));
                        builder.append(LocaleController.getString(R.string.UnitCNY));
                    }
                } else if (status == 1) {
                    RedpacketBean res = RedpktGroupStateActivity.this.bean.getRed();
                    builder.append(res.getNumber());
                    builder.append(LocaleController.getString(R.string.redpacket_each));
                    builder.append(LocaleController.getString(R.string.RedPacket));
                    builder.append(LocaleController.getString(R.string.Comma));
                    builder.append(res.getDuration());
                } else {
                    builder.append(LocaleController.getString(R.string.RedpacketHadExpired));
                    builder.append(LocaleController.getString(R.string.Comma));
                    builder.append(LocaleController.getString(R.string.AlreadyReceive));
                    builder.append(RedpktGroupStateActivity.this.bean.getRed().getNumber() - RedpktGroupStateActivity.this.bean.getRed().getSurplusNumber());
                    builder.append("/");
                    builder.append(RedpktGroupStateActivity.this.bean.getRed().getNumber());
                    builder.append(LocaleController.getString(R.string.Comma));
                    builder.append(LocaleController.getString(R.string.TotalSingleWords));
                    builder.append(DataTools.format2Decimals(subtract.divide(new BigDecimal("100")).toString()));
                    builder.append("/");
                    builder.append(DataTools.format2Decimals(total.divide(new BigDecimal("100")).toString()));
                    builder.append(LocaleController.getString(R.string.UnitCNY));
                }
                cell.setText(builder.toString());
                return;
            }
            BackupImageView ivAvatar = (BackupImageView) holder.itemView.findViewById(R.attr.iv_avatar);
            TextView tvName = (TextView) holder.itemView.findViewById(R.attr.tv_type_and_from);
            TextView tvCGnum = (TextView) holder.itemView.findViewById(R.attr.tv_CG_num);
            TextView tvCollectTime = (TextView) holder.itemView.findViewById(R.attr.tv_time);
            TextView tvFeatureBest = (TextView) holder.itemView.findViewById(R.attr.tv_state);
            TextView tvMoneyUnit = (TextView) holder.itemView.findViewById(R.attr.tvMoneyUnit);
            RedpacketDetailRecord redpkgRecord = (RedpacketDetailRecord) RedpktGroupStateActivity.this.records.get(position - 2);
            ImageView ivFeatureImage = (ImageView) holder.itemView.findViewById(R.attr.iv_best);
            TLRPC.User receiver = RedpktGroupStateActivity.this.getMessagesController().getUser(Integer.valueOf(Integer.parseInt(redpkgRecord.getUserId())));
            if (receiver == null) {
                charSequence = "";
            } else {
                AvatarDrawable avatarDrawable2 = new AvatarDrawable();
                avatarDrawable2.setTextSize(AndroidUtilities.dp(16.0f));
                avatarDrawable2.setInfo(receiver);
                ivAvatar.setRoundRadius(AndroidUtilities.dp(32.0f));
                charSequence = "";
                ivAvatar.getImageReceiver().setCurrentAccount(RedpktGroupStateActivity.this.currentAccount);
                ivAvatar.setImage(ImageLocation.getForUser(receiver, false), "50_50", avatarDrawable2, receiver);
                tvName.setText(receiver.first_name);
            }
            BigDecimal money = new BigDecimal(redpkgRecord.getTotalFee());
            tvCGnum.setText(DataTools.format2Decimals(money.divide(new BigDecimal("100")).toString()));
            tvMoneyUnit.setText(LocaleController.getString(R.string.UnitCNY));
            tvCollectTime.setText(redpkgRecord.getCreateTimeFormat());
            if ("1".equals(redpkgRecord.getIsOptimum()) && RedpktGroupStateActivity.this.isRandom) {
                tvFeatureBest.setVisibility(0);
                ivFeatureImage.setVisibility(0);
                tvFeatureBest.setText(LocaleController.getString(R.string.BestOfLuck));
                tvFeatureBest.setTextColor(-2737326);
                return;
            }
            tvFeatureBest.setText(charSequence);
            ivFeatureImage.setVisibility(8);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return RedpktGroupStateActivity.this.rowCount;
        }
    }
}
