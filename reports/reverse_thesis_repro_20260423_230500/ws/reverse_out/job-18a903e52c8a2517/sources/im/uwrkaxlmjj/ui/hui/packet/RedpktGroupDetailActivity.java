package im.uwrkaxlmjj.ui.hui.packet;

import android.content.Context;
import android.content.DialogInterface;
import android.text.Html;
import android.text.Layout;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.BindView;
import com.google.gson.Gson;
import im.uwrkaxlmjj.javaBean.hongbao.RedTransOperation;
import im.uwrkaxlmjj.javaBean.hongbao.UnifyBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.utils.DataTools;
import im.uwrkaxlmjj.messenger.utils.TextTool;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCRedpacket;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketBean;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketDetailRecord;
import im.uwrkaxlmjj.ui.hui.packet.bean.RedpacketDetailResponse;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.utils.number.StringUtils;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RedpktGroupDetailActivity extends BaseFragment {
    private RedpacketBean bean;
    private TLRPC.Chat chat;
    private boolean isLoaded;
    private boolean isLoading;
    private boolean isRandom;
    private ListAdapter listAdapter;
    private int messageId;

    @BindView(R.attr.rcy_rpk_history)
    RecyclerListView rcyRpkHistory;
    private ArrayList<RedpacketDetailRecord> records;
    private MryTextView rptView;

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

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        super.onTransitionAnimationEnd(isOpen, backward);
        if (isOpen) {
            getRecords();
        }
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
        this.actionBar.getBackButton().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupDetailActivity$WJ6n8TpLZ4vJ4oJlvss1qSqV9RQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$0$RedpktGroupDetailActivity(view);
            }
        });
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.packet.RedpktGroupDetailActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    RedpktGroupDetailActivity.this.finishFragment();
                } else if (id == 101) {
                    RedpktRecordsActivity recordsActivity = new RedpktRecordsActivity();
                    RedpktGroupDetailActivity.this.presentFragment(recordsActivity);
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

    public /* synthetic */ void lambda$initActionBar$0$RedpktGroupDetailActivity(View v) {
        finishFragment();
    }

    public void setBean(RedpacketBean bean) {
        this.bean = bean;
        if (bean != null && bean.getGrantType() != null) {
            this.isRandom = "1".equals(bean.getGrantType());
        }
    }

    public void setChat(TLRPC.Chat chat) {
        this.chat = chat;
    }

    public void setMessageId(int mid) {
        this.messageId = mid;
    }

    private void updateRows() {
        this.headerRow = -1;
        this.headerSessionRow = -1;
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.headerRow = 0;
        this.rowCount = i + 1;
        this.headerSessionRow = i;
        ArrayList<RedpacketDetailRecord> arrayList = this.records;
        if (arrayList != null && arrayList.size() > 0) {
            Log.d("bond", "size = " + this.records.size());
            this.rowCount = this.rowCount + this.records.size();
        }
    }

    private void initViews() {
        this.rcyRpkHistory.setLayoutManager(new LinearLayoutManager(getParentActivity()));
        ListAdapter listAdapter = new ListAdapter(getParentActivity());
        this.listAdapter = listAdapter;
        this.rcyRpkHistory.setAdapter(listAdapter);
        this.tvRpkBackDesc.setText(LocaleController.getString(R.string.RedPacketsWillReturnWhenNotReceivedIn24Hours));
    }

    private void getRecords() {
        if (this.isLoading) {
            return;
        }
        this.isLoading = true;
        TLRPCRedpacket.CL_message_rpkTransferCheck req = new TLRPCRedpacket.CL_message_rpkTransferCheck();
        req.trans = 0;
        if (this.chat != null) {
            int redType = this.bean.getRedTypeInt();
            if (redType == 0) {
                req.type = 2;
            } else if (redType == 1) {
                req.type = 1;
            } else if (redType == 2) {
                req.type = 3;
            }
        } else {
            req.type = 0;
        }
        req.flags = 2;
        TLRPC.InputPeer inputPeer = new TLRPC.TL_inputPeerChannel();
        inputPeer.channel_id = this.chat.id;
        inputPeer.access_hash = this.chat.access_hash;
        req.peer = inputPeer;
        req.id = this.messageId;
        String serialCode = this.bean.getSerialCode();
        String str = getUserConfig().clientUserId + "";
        TLRPC.Chat chat = this.chat;
        RedTransOperation detailBean = new RedTransOperation(serialCode, str, chat == null ? "" : String.valueOf(chat.id), StringUtils.getNonceStr(getConnectionsManager().getCurrentTime()), UnifyBean.BUSINESS_KEY_REDPACKET_DETAIL, "0.0.1");
        TLRPC.TL_dataJSON dataJSON = new TLRPC.TL_dataJSON();
        dataJSON.data = new Gson().toJson(detailBean);
        req.data = dataJSON;
        final XAlertDialog progressView = new XAlertDialog(getParentActivity(), 5);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupDetailActivity$W5KrS8R_kiKWbvHf4iqqyHQWLOM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getRecords$3$RedpktGroupDetailActivity(progressView, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
        progressView.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupDetailActivity$4AVyZ5Um9AA04uS3xRrNbzmIW-g
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$getRecords$4$RedpktGroupDetailActivity(reqId, dialogInterface);
            }
        });
        progressView.show();
    }

    public /* synthetic */ void lambda$getRecords$3$RedpktGroupDetailActivity(final XAlertDialog progressView, TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupDetailActivity$_16ClWPUoS0O0xgM6SHRtYxT0ns
            @Override // java.lang.Runnable
            public final void run() {
                progressView.dismiss();
            }
        });
        this.isLoading = false;
        if (error != null) {
            if (!BuildVars.RELEASE_VERSION) {
                AlertsCreator.showSimpleToast(this, WalletErrorUtil.getErrorDescription(LocaleController.formatString("SystemIsBusyAndTryAgainLater", R.string.SystemIsBusyAndTryAgainLater, new Object[0]), error.text));
                return;
            } else {
                WalletDialogUtil.showConfirmBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(error.text));
                return;
            }
        }
        if (response instanceof TLRPC.TL_updates) {
            TLRPC.TL_updates updates = (TLRPC.TL_updates) response;
            for (TLRPC.Update update : updates.updates) {
                if (update instanceof TLRPCRedpacket.CL_updateRpkTransfer) {
                    TLRPCRedpacket.CL_updateRpkTransfer rpkTransfer = (TLRPCRedpacket.CL_updateRpkTransfer) update;
                    TLApiModel<RedpacketDetailResponse> parse = TLJsonResolve.parse(rpkTransfer.data, (Class<?>) RedpacketDetailResponse.class);
                    if (parse.isSuccess() || "20004".equals(parse.code) || "20013".equals(parse.code) || "20008".equals(parse.code)) {
                        RedpacketDetailResponse retBean = parse.model;
                        if (retBean != null) {
                            this.isLoaded = true;
                            this.bean = retBean.getRed();
                            ArrayList<RedpacketDetailRecord> record = retBean.getRecord();
                            this.records = record;
                            groupsRecords(record);
                            updateRows();
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupDetailActivity$cfN3Zc0M5-obfSuHQxXq71IgC-Y
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$null$2$RedpktGroupDetailActivity();
                                }
                            });
                            return;
                        }
                        return;
                    }
                    if (BuildVars.RELEASE_VERSION) {
                        WalletErrorUtil.parseErrorDialog(this, LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater));
                        return;
                    } else {
                        WalletErrorUtil.parseErrorDialog(this, parse.code, parse.message);
                        return;
                    }
                }
            }
        }
    }

    public /* synthetic */ void lambda$null$2$RedpktGroupDetailActivity() {
        this.listAdapter.notifyDataSetChanged();
    }

    public /* synthetic */ void lambda$getRecords$4$RedpktGroupDetailActivity(int reqId, DialogInterface hintDialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    private void groupsRecords(ArrayList<RedpacketDetailRecord> record) {
        if (record == null || record.size() <= 0) {
            return;
        }
        Collections.sort(record, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.packet.-$$Lambda$RedpktGroupDetailActivity$YmAXKyOD1klBSvaHH-RlrN58JkY
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return RedpktGroupDetailActivity.lambda$groupsRecords$5((RedpacketDetailRecord) obj, (RedpacketDetailRecord) obj2);
            }
        });
    }

    static /* synthetic */ int lambda$groupsRecords$5(RedpacketDetailRecord o1, RedpacketDetailRecord o2) {
        if (o1.getCreatTimeLong() > o2.getCreatTimeLong()) {
            return 1;
        }
        if (o1.getCreatTimeLong() < o2.getCreatTimeLong()) {
            return -1;
        }
        return 0;
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
            } else if (viewType == 1) {
                view = LayoutInflater.from(this.mContext).inflate(R.layout.item_red_packet_group_info_layout, (ViewGroup) null);
                view.setBackgroundColor(-1);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(70.0f)));
            } else {
                view = LayoutInflater.from(this.mContext).inflate(R.layout.item_red_packet_records, (ViewGroup) null);
                view.setBackgroundColor(-1);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(72.0f)));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != RedpktGroupDetailActivity.this.headerRow) {
                if (position == RedpktGroupDetailActivity.this.headerSessionRow) {
                    return 1;
                }
                return 2;
            }
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String str;
            TLRPC.User recvUser;
            if (position == 0) {
                BackupImageView ivRptAvatar = (BackupImageView) holder.itemView.findViewById(R.attr.ivRptAvatar);
                BackupImageView zsAvatar = (BackupImageView) holder.itemView.findViewById(R.attr.zsAvatar);
                LinearLayout zsLayout = (LinearLayout) holder.itemView.findViewById(R.attr.zsLayout);
                TextView zsText = (TextView) holder.itemView.findViewById(R.attr.zsText);
                TextView tvRptName = (TextView) holder.itemView.findViewById(R.attr.tvRptName);
                TextView tvRptGreet = (TextView) holder.itemView.findViewById(R.attr.tvRptGreet);
                TextView tvReceivedCount = (TextView) holder.itemView.findViewById(R.attr.tvReceivedCount);
                TextView tvReceivedPromt = (TextView) holder.itemView.findViewById(R.attr.tvReceivedPromt);
                ImageView ivHotCoinLogo = (ImageView) holder.itemView.findViewById(R.attr.ivHotCoinLogo);
                TLRPC.User sender = RedpktGroupDetailActivity.this.getMessagesController().getUser(Integer.valueOf(Integer.parseInt(RedpktGroupDetailActivity.this.bean.getInitiatorUserId())));
                if (sender != null) {
                    AvatarDrawable avatarDrawable = new AvatarDrawable();
                    avatarDrawable.setTextSize(AndroidUtilities.dp(16.0f));
                    avatarDrawable.setInfo(sender);
                    ivRptAvatar.setRoundRadius(AndroidUtilities.dp(7.5f));
                    str = "100";
                    ivRptAvatar.getImageReceiver().setCurrentAccount(RedpktGroupDetailActivity.this.currentAccount);
                    ivRptAvatar.setImage(ImageLocation.getForUser(sender, false), "50_50", avatarDrawable, sender);
                    tvRptName.setText(UserObject.getName(sender, 16));
                    int redType = RedpktGroupDetailActivity.this.bean.getRedTypeInt();
                    if (redType == 2 && ((sender.id == RedpktGroupDetailActivity.this.getUserConfig().getCurrentUser().id || (sender.id != RedpktGroupDetailActivity.this.getUserConfig().getCurrentUser().id && RedpktGroupDetailActivity.this.bean.getRecipientUserIdInt() != RedpktGroupDetailActivity.this.getUserConfig().getCurrentUser().id)) && (recvUser = RedpktGroupDetailActivity.this.getMessagesController().getUser(Integer.valueOf(RedpktGroupDetailActivity.this.bean.getRecipientUserIdInt()))) != null)) {
                        zsLayout.setVisibility(0);
                        AvatarDrawable recvDrawable = new AvatarDrawable();
                        recvDrawable.setTextSize(AndroidUtilities.dp(16.0f));
                        recvDrawable.setInfo(sender);
                        zsAvatar.setRoundRadius(AndroidUtilities.dp(3.0f));
                        zsAvatar.getImageReceiver().setCurrentAccount(RedpktGroupDetailActivity.this.currentAccount);
                        zsAvatar.setImage(ImageLocation.getForUser(recvUser, false), "50_50", recvDrawable, recvUser);
                        zsText.setText(UserObject.getName(recvUser, 10) + LocaleController.getString("Exclusive", R.string.Exclusive));
                    }
                } else {
                    str = "100";
                }
                if (RedpktGroupDetailActivity.this.bean.getRemarks() != null && !TextUtils.isEmpty(RedpktGroupDetailActivity.this.bean.getRemarks())) {
                    tvRptGreet.setText(RedpktGroupDetailActivity.this.bean.getRemarks());
                    tvRptGreet.setTextColor(-1);
                } else {
                    tvRptGreet.setText(LocaleController.getString(R.string.redpacket_greetings_tip));
                    tvRptGreet.setTextColor(-1);
                }
                if (RedpktGroupDetailActivity.this.bean.getIsReceived() == 0 || RedpktGroupDetailActivity.this.isLoading || !RedpktGroupDetailActivity.this.isLoaded) {
                    tvReceivedCount.setVisibility(8);
                    tvReceivedPromt.setVisibility(8);
                    ivHotCoinLogo.setVisibility(8);
                    return;
                }
                tvReceivedCount.setVisibility(0);
                tvReceivedPromt.setVisibility(0);
                ivHotCoinLogo.setVisibility(0);
                BigDecimal bigDecimal = new BigDecimal(String.valueOf(RedpktGroupDetailActivity.this.bean.getMoney()));
                TextTool.Builder textBuilder = TextTool.getBuilder("").setContext(RedpktGroupDetailActivity.this.getParentActivity()).setBold().setAlign(Layout.Alignment.ALIGN_CENTER).append(DataTools.format2Decimals(bigDecimal.divide(new BigDecimal(str)).toString())).setForegroundColor(-3416).setProportion(2.0f).append(LocaleController.getString(R.string.UnitCNY));
                textBuilder.into(tvReceivedCount);
                tvReceivedPromt.setText(Html.fromHtml(LocaleController.getString(R.string.ViewWalletBalance)));
                return;
            }
            if (position == 1) {
                TextView cell = (TextView) holder.itemView.findViewById(R.attr.tvRecvStatus);
                if (cell != null) {
                    cell.setPadding(AndroidUtilities.dp(16.0f), 0, AndroidUtilities.dp(16.0f), 0);
                    cell.setGravity(16);
                    BigDecimal total = new BigDecimal(RedpktGroupDetailActivity.this.bean.getTotalFee());
                    BigDecimal extal = new BigDecimal(RedpktGroupDetailActivity.this.bean.getSurplusAmount());
                    BigDecimal subtract = total.subtract(extal);
                    int redType2 = Integer.parseInt(RedpktGroupDetailActivity.this.bean.getRedType());
                    int status = Integer.parseInt(RedpktGroupDetailActivity.this.bean.getStatus());
                    StringBuilder builder = new StringBuilder("");
                    if (redType2 == 2) {
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
                            RedpktGroupDetailActivity.this.tvRpkBackDesc.setVisibility(8);
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
                        if (RedpktGroupDetailActivity.this.records == null || RedpktGroupDetailActivity.this.records.size() == 0) {
                            builder.append(RedpktGroupDetailActivity.this.bean.getNumber());
                            builder.append(LocaleController.getString(R.string.redpacket_each));
                            builder.append(LocaleController.getString(R.string.RedPacket));
                            builder.append(LocaleController.getString(R.string.TotalSingleWords));
                            builder.append(DataTools.format2Decimals(total.divide(new BigDecimal("100")).toString()));
                            builder.append(LocaleController.getString(R.string.UnitCNY));
                            builder.append(LocaleController.getString(R.string.Comma));
                            builder.append(LocaleController.getString(R.string.WaitToReceived));
                        } else {
                            builder.append(LocaleController.getString(R.string.AlreadyReceive));
                            builder.append(RedpktGroupDetailActivity.this.bean.getNumber() - RedpktGroupDetailActivity.this.bean.getSurplusNumber());
                            builder.append("/");
                            builder.append(RedpktGroupDetailActivity.this.bean.getNumber());
                            builder.append(LocaleController.getString("Each", R.string.redpacket_each));
                            builder.append(",");
                            builder.append(LocaleController.getString(R.string.TotalSingleWords));
                            builder.append(DataTools.format2Decimals(subtract.divide(new BigDecimal("100")).toString()));
                            builder.append("/");
                            builder.append(DataTools.format2Decimals(total.divide(new BigDecimal("100")).toString()));
                            builder.append(LocaleController.getString(R.string.UnitCNY));
                        }
                    } else if (status == 1) {
                        builder.append(RedpktGroupDetailActivity.this.bean.getNumber());
                        builder.append(LocaleController.getString(R.string.redpacket_each));
                        builder.append(LocaleController.getString(R.string.RedPacket));
                        builder.append(LocaleController.getString(R.string.Comma));
                        builder.append(RedpktGroupDetailActivity.this.bean.getDuration());
                        RedpktGroupDetailActivity.this.tvRpkBackDesc.setVisibility(8);
                    } else {
                        builder.append(LocaleController.getString(R.string.RedpacketHadExpired));
                        builder.append(LocaleController.getString(R.string.Comma));
                        builder.append(LocaleController.getString(R.string.AlreadyReceive));
                        builder.append(RedpktGroupDetailActivity.this.bean.getNumber() - RedpktGroupDetailActivity.this.bean.getSurplusNumber());
                        builder.append("/");
                        builder.append(RedpktGroupDetailActivity.this.bean.getNumber());
                        builder.append(LocaleController.getString(R.string.Comma));
                        builder.append(LocaleController.getString(R.string.TotalSingleWords));
                        builder.append(DataTools.format2Decimals(subtract.multiply(new BigDecimal("0.01")).toString()));
                        builder.append("/");
                        builder.append(DataTools.format2Decimals(total.multiply(new BigDecimal("0.01")).toString()));
                        builder.append(LocaleController.getString(R.string.UnitCNY));
                    }
                    cell.setText(builder.toString());
                    return;
                }
                return;
            }
            BackupImageView ivAvatar = (BackupImageView) holder.itemView.findViewById(R.attr.iv_avatar);
            TextView tvName = (TextView) holder.itemView.findViewById(R.attr.tv_type_and_from);
            TextView tvCGnum = (TextView) holder.itemView.findViewById(R.attr.tv_CG_num);
            TextView tvCollectTime = (TextView) holder.itemView.findViewById(R.attr.tv_time);
            TextView tvFeatureBest = (TextView) holder.itemView.findViewById(R.attr.tv_state);
            RedpacketDetailRecord redpkgRecord = (RedpacketDetailRecord) RedpktGroupDetailActivity.this.records.get(position - 2);
            ImageView ivFeatureImage = (ImageView) holder.itemView.findViewById(R.attr.iv_best);
            TLRPC.User receiver = RedpktGroupDetailActivity.this.getMessagesController().getUser(Integer.valueOf(Integer.parseInt(redpkgRecord.getUserId())));
            if (receiver != null) {
                AvatarDrawable avatarDrawable2 = new AvatarDrawable();
                avatarDrawable2.setTextSize(AndroidUtilities.dp(16.0f));
                avatarDrawable2.setInfo(receiver);
                ivAvatar.setRoundRadius(AndroidUtilities.dp(7.5f));
                ivAvatar.getImageReceiver().setCurrentAccount(RedpktGroupDetailActivity.this.currentAccount);
                ivAvatar.setImage(ImageLocation.getForUser(receiver, false), "50_50", avatarDrawable2, receiver);
                tvName.setText(receiver.first_name);
            }
            BigDecimal money = new BigDecimal(redpkgRecord.getTotalFee());
            tvCGnum.setText(DataTools.format2Decimals(money.divide(new BigDecimal("100")).toString()));
            tvCollectTime.setText(redpkgRecord.getCreateTimeFormat());
            if ("1".equals(redpkgRecord.getIsOptimum()) && RedpktGroupDetailActivity.this.isRandom) {
                tvFeatureBest.setVisibility(0);
                ivFeatureImage.setVisibility(0);
                tvFeatureBest.setText(LocaleController.getString(R.string.BestOfLuck));
                tvFeatureBest.setTextColor(-85688);
                return;
            }
            tvFeatureBest.setText("");
            ivFeatureImage.setVisibility(8);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return RedpktGroupDetailActivity.this.rowCount;
        }
    }
}
