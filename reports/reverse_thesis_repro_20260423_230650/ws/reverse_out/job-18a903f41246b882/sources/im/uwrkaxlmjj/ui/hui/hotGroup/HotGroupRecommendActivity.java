package im.uwrkaxlmjj.ui.hui.hotGroup;

import android.content.Context;
import android.content.DialogInterface;
import android.content.res.ColorStateList;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCHotChannel;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter;
import im.uwrkaxlmjj.ui.hui.chats.CreateGroupActivity;
import im.uwrkaxlmjj.ui.hui.decoration.TopBottomDecoration;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class HotGroupRecommendActivity extends BaseFragment {
    private PageSelectionAdapter<Item, PageHolder> adapter;
    private RecyclerListView rv;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        initActionBar();
        initView(context);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString(R.string.HotChannelRecommend));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addItem(1, R.drawable.groups_create);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.hotGroup.HotGroupRecommendActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    HotGroupRecommendActivity.this.finishFragment();
                } else {
                    Bundle args = new Bundle();
                    HotGroupRecommendActivity.this.presentFragment(new CreateGroupActivity(args));
                }
            }
        });
    }

    private void initView(Context context) {
        FrameLayout root = new FrameLayout(context);
        root.setLayoutParams(LayoutHelper.createFrame(-1, -1.0f));
        this.fragmentView = root;
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.rv = recyclerListView;
        root.addView(recyclerListView, LayoutHelper.createFrame(-1, -1, AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 10));
        this.rv.setLayoutManager(new LinearLayoutManager(context));
        this.rv.addItemDecoration(TopBottomDecoration.getDefaultTopBottomCornerBg(10, 10, 8.0f));
        AnonymousClass2 anonymousClass2 = new AnonymousClass2(context);
        this.adapter = anonymousClass2;
        this.rv.setAdapter(anonymousClass2);
        this.adapter.emptyAttachView(root);
        this.adapter.showLoading();
        getData(this.adapter.getStartPage());
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.hotGroup.HotGroupRecommendActivity$2, reason: invalid class name */
    class AnonymousClass2 extends PageSelectionAdapter<Item, PageHolder> {
        AnonymousClass2(Context context) {
            super(context);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public PageHolder onCreateViewHolderForChild(ViewGroup parent, int viewType) {
            return new PageHolder(LayoutInflater.from(getContext()).inflate(R.layout.hot_group_item_recommend_list, parent, false), 0);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
        public void onBindViewHolderForChild(PageHolder holder, int position, final Item item) {
            boolean z;
            int i;
            BackupImageView ivAvatar = (BackupImageView) holder.getView(R.attr.ivAvatar);
            MryTextView tvTitle = (MryTextView) holder.getView(R.attr.tvTitle);
            MryTextView tvDescription = (MryTextView) holder.getView(R.attr.tvDescription);
            MryRoundButton tvTag = (MryRoundButton) holder.getView(R.attr.tvTag);
            MryRoundButton btn = (MryRoundButton) holder.getView(R.attr.btn);
            MryTextView tvCount = (MryTextView) holder.getView(R.attr.tvCount);
            View divider = holder.getView(R.attr.divider);
            tvCount.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
            ivAvatar.setRoundRadius(AndroidUtilities.dp(5.0f));
            ivAvatar.setImageResource(R.drawable.bg_comment_grey_line);
            boolean isInThisGroup = false;
            if (item.chat != null) {
                AvatarDrawable avatarDrawable = new AvatarDrawable();
                z = false;
                ivAvatar.setImage(ImageLocation.getForChat(item.chat, false), "50_50", "", avatarDrawable, item.chat);
                tvTitle.setText(item.chat.title);
                TLRPC.Chat targetChat = HotGroupRecommendActivity.this.getMessagesController().getChat(Integer.valueOf(item.chat.id));
                isInThisGroup = (targetChat == null || targetChat.left) ? false : true;
                tvCount.setText(String.valueOf(item.chat.participants_count));
            } else {
                z = false;
            }
            if (isInThisGroup) {
                btn.setPrimaryRadiusAdjustBoundsStrokeStyle();
                btn.setStrokeColors(ColorStateList.valueOf(-2250382));
                btn.setTextColor(-2250382);
                btn.setText(LocaleController.getString(R.string.EnterGroup));
            } else {
                btn.setBackgroundResource(R.id.hot_group_list_btn);
                btn.setTextColor(-1);
                btn.setText(LocaleController.getString(R.string.JoinNow));
            }
            if (item.groupAbout != null) {
                if (!TextUtils.isEmpty(item.groupAbout.about)) {
                    holder.setGone(tvDescription, z);
                    tvDescription.setText(item.groupAbout.about);
                } else {
                    holder.setGone((View) tvDescription, true);
                }
                if (!TextUtils.isEmpty(item.groupAbout.groupType)) {
                    holder.setGone(tvTag, z);
                    tvTag.setPrimaryRoundFillStyle(AndroidUtilities.dp(5.0f));
                    tvTag.setBackgroundColor(282962290);
                    tvTag.setTextColor(-2250382);
                    i = 1;
                    tvTag.setStrokeData(1, -2250382);
                    tvTag.setText(item.groupAbout.groupType);
                } else {
                    i = 1;
                    holder.setGone((View) tvTag, true);
                }
            } else {
                i = 1;
                holder.setGone((View) tvTag, true);
                holder.setGone((View) tvDescription, true);
            }
            btn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.hotGroup.-$$Lambda$HotGroupRecommendActivity$2$Z2TQBs1o6tjUhcRsBungQo9rHLQ
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onBindViewHolderForChild$0$HotGroupRecommendActivity$2(item, view);
                }
            });
            holder.setGone(divider, position == getDataCount() - i);
        }

        public /* synthetic */ void lambda$onBindViewHolderForChild$0$HotGroupRecommendActivity$2(Item item, View v) {
            HotGroupRecommendActivity.this.clickBtn(item.chat);
        }

        @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter, im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageLoadMoreListener
        public void loadData(int page) {
            HotGroupRecommendActivity.this.getData(page);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getData(int page) {
        TLRPCHotChannel.TL_GetHotGroups req = new TLRPCHotChannel.TL_GetHotGroups();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.hotGroup.-$$Lambda$HotGroupRecommendActivity$b053Wyz_wHTvQmISJgwGhV4N8Gc
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getData$1$HotGroupRecommendActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$getData$1$HotGroupRecommendActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.hotGroup.-$$Lambda$HotGroupRecommendActivity$ONNYirhMr6ZW0Rto7gyj_xGmY34
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$HotGroupRecommendActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$HotGroupRecommendActivity(TLRPC.TL_error error, TLObject response) {
        if (error == null && (response instanceof TLRPCHotChannel.TL_HotGroups)) {
            TLRPCHotChannel.TL_HotGroups res = (TLRPCHotChannel.TL_HotGroups) response;
            List<Item> data = new ArrayList<>();
            for (TLRPCHotChannel.TL_HotGroupAbout a : res.getPeers()) {
                data.add(new Item(a));
            }
            for (int i = 0; i < res.getChats().size(); i++) {
                if (i < data.size()) {
                    data.get(i).chat = res.getChats().get(i);
                }
            }
            PageSelectionAdapter<Item, PageHolder> pageSelectionAdapter = this.adapter;
            if (pageSelectionAdapter != null) {
                pageSelectionAdapter.addData(data);
                return;
            }
            return;
        }
        ToastUtils.show(R.string.NetworkError);
        PageSelectionAdapter<Item, PageHolder> pageSelectionAdapter2 = this.adapter;
        if (pageSelectionAdapter2 != null) {
            pageSelectionAdapter2.showError(LocaleController.getString(R.string.NetworkError));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void clickBtn(TLRPC.Chat chat) {
        if (chat == null) {
            return;
        }
        TLRPC.Chat targetChat = getMessagesController().getChat(Integer.valueOf(chat.id));
        if (targetChat != null) {
            if (targetChat.kicked) {
                WalletDialogUtil.showConfirmBtnWalletDialog(this, LocaleController.getString(R.string.CannotJoinGroupWhenKickedOut));
                return;
            } else if (!targetChat.left) {
                Bundle args = new Bundle();
                args.putInt("chat_id", targetChat.id);
                presentFragment(new ChatActivity(args));
                return;
            }
        }
        joinChannel(chat);
    }

    private void joinChannel(final TLRPC.Chat channel) {
        TLRPC.TL_channels_joinChannel req = new TLRPC.TL_channels_joinChannel();
        req.channel = MessagesController.getInputChannel(channel);
        final int currentAccount = UserConfig.selectedAccount;
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.hotGroup.-$$Lambda$HotGroupRecommendActivity$gdKfbuKHpzff1UD145rActshLaM
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$joinChannel$2$HotGroupRecommendActivity(dialogInterface);
            }
        });
        progressDialog.show();
        final int reqId = ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.hotGroup.-$$Lambda$HotGroupRecommendActivity$k0xcNRA0eXSkIDP5Wn3UdstUCi4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws Exception {
                this.f$0.lambda$joinChannel$6$HotGroupRecommendActivity(progressDialog, currentAccount, channel, tLObject, tL_error);
            }
        });
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.hotGroup.-$$Lambda$HotGroupRecommendActivity$-LQLAfTLyB-S1ZK4ZMi1dQ_yEcA
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$joinChannel$7$HotGroupRecommendActivity(reqId, dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$joinChannel$2$HotGroupRecommendActivity(DialogInterface dialog) {
        getConnectionsManager().cancelRequestsForGuid(this.classGuid);
    }

    public /* synthetic */ void lambda$joinChannel$6$HotGroupRecommendActivity(final AlertDialog progressDialog, final int currentAccount, final TLRPC.Chat channel, TLObject response, TLRPC.TL_error error) throws Exception {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.hotGroup.-$$Lambda$HotGroupRecommendActivity$LQ_OIV2aj-EmhKrY9dWvaY3h2_8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$3$HotGroupRecommendActivity(progressDialog);
                }
            });
            return;
        }
        boolean hasJoinMessage = false;
        TLRPC.Updates updates = (TLRPC.Updates) response;
        int a = 0;
        while (true) {
            if (a >= updates.updates.size()) {
                break;
            }
            TLRPC.Update update = updates.updates.get(a);
            if (!(update instanceof TLRPC.TL_updateNewChannelMessage) || !(((TLRPC.TL_updateNewChannelMessage) update).message.action instanceof TLRPC.TL_messageActionChatAddUser)) {
                a++;
            } else {
                hasJoinMessage = true;
                break;
            }
        }
        MessagesController.getInstance(currentAccount).processUpdates(updates, false);
        if (!hasJoinMessage) {
            MessagesController.getInstance(currentAccount).generateJoinMessage(channel.id, true);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.hotGroup.-$$Lambda$HotGroupRecommendActivity$w5NCDIyDIxuC_2Hsx_bQXFALTcI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$HotGroupRecommendActivity(progressDialog, currentAccount, channel);
            }
        }, 1000L);
        MessagesStorage.getInstance(currentAccount).updateDialogsWithDeletedMessages(new ArrayList<>(), null, true, channel.id);
    }

    public /* synthetic */ void lambda$null$3$HotGroupRecommendActivity(AlertDialog progressDialog) {
        if (progressDialog != null) {
            progressDialog.dismiss();
        }
        WalletDialogUtil.showConfirmBtnWalletDialog(this, LocaleController.getString("Tips", R.string.Tips), LocaleController.getString(R.string.discovery_join_group_error), false, null, null);
    }

    public /* synthetic */ void lambda$null$5$HotGroupRecommendActivity(AlertDialog progressDialog, int currentAccount, final TLRPC.Chat channel) {
        if (progressDialog != null) {
            progressDialog.dismiss();
        }
        MessagesController.getInstance(currentAccount).loadFullChat(channel.id, 0, true);
        WalletDialogUtil.showSingleBtnWalletDialog(this, LocaleController.getString("Tips", R.string.Tips), LocaleController.getString(R.string.discovery_join_group_success), LocaleController.getString(R.string.OK), false, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.hotGroup.-$$Lambda$HotGroupRecommendActivity$IhpHw1ljBzsAQTdtwlfBn-3q1b4
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$4$HotGroupRecommendActivity(channel, dialogInterface, i);
            }
        }, null);
        getData(this.adapter.getStartPage());
    }

    public /* synthetic */ void lambda$null$4$HotGroupRecommendActivity(TLRPC.Chat channel, DialogInterface dialog, int which) {
        channel.left = false;
        Bundle args = new Bundle();
        args.putInt("chat_id", channel.id);
        presentFragment(new ChatActivity(args));
    }

    public /* synthetic */ void lambda$joinChannel$7$HotGroupRecommendActivity(int reqId, DialogInterface dialog) {
        getConnectionsManager().cancelRequest(reqId, true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        this.rv = null;
        PageSelectionAdapter<Item, PageHolder> pageSelectionAdapter = this.adapter;
        if (pageSelectionAdapter != null) {
            pageSelectionAdapter.destroy();
            this.adapter = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class Item {
        TLRPC.Chat chat;
        TLRPCHotChannel.TL_HotGroupAbout groupAbout;

        Item(TLRPCHotChannel.TL_HotGroupAbout groupAbout) {
            this.groupAbout = groupAbout;
        }
    }
}
