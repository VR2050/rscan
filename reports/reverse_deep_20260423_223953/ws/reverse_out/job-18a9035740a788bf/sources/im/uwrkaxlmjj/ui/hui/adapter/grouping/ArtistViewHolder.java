package im.uwrkaxlmjj.ui.hui.adapter.grouping;

import android.content.DialogInterface;
import android.os.Bundle;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.expand.models.ExpandableGroup;
import im.uwrkaxlmjj.ui.expand.viewholders.ChildViewHolder;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ArtistViewHolder extends ChildViewHolder {
    private GenreAdapter adapter;
    private Artist artist;
    private Genre genre;
    private BackupImageView ivAvatar;
    private MryTextView tvName;
    private MryTextView tvStatus;
    private TLRPC.User user;

    public ArtistViewHolder(View itemView) {
        super(itemView);
        final SwipeLayout swipeLayout = (SwipeLayout) itemView;
        swipeLayout.setItemWidth(AndroidUtilities.dp(86.0f));
        View content = swipeLayout.getMainLayout();
        this.ivAvatar = (BackupImageView) content.findViewById(R.attr.iv_item_artist_avatar);
        this.tvName = (MryTextView) content.findViewById(R.attr.list_item_artist_name);
        this.tvStatus = (MryTextView) content.findViewById(R.attr.list_item_artist_status);
        int[] rightColors = {-570319};
        String[] rightTexts = {LocaleController.getString(R.string.RemoveFromGrouping)};
        int[] rightTextColors = {-1};
        swipeLayout.setRightTexts(rightTexts);
        swipeLayout.setRightTextColors(rightTextColors);
        swipeLayout.setRightColors(rightColors);
        swipeLayout.setTextSize(AndroidUtilities.sp2px(14.0f));
        swipeLayout.rebuildLayout();
        swipeLayout.setOnSwipeItemClickListener(new SwipeLayout.OnSwipeItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.adapter.grouping.-$$Lambda$ArtistViewHolder$NegPuBx9bncvteFIXIuuA35REgg
            @Override // im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout.OnSwipeItemClickListener
            public final void onSwipeItemClick(boolean z, int i) {
                this.f$0.lambda$new$3$ArtistViewHolder(z, i);
            }
        });
        content.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.adapter.grouping.-$$Lambda$ArtistViewHolder$tA1ZUFzeuP2LMsxnOV2TaK0xDWc
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$4$ArtistViewHolder(swipeLayout, view);
            }
        });
    }

    public /* synthetic */ void lambda$new$3$ArtistViewHolder(boolean left, int index) {
        if (!left && index == 0 && this.genre.getGroupId() != 0) {
            final ConnectionsManager connectionsManager = ConnectionsManager.getInstance(UserConfig.selectedAccount);
            final AlertDialog alertDialog = new AlertDialog(this.adapter.getActivity().getParentActivity(), 3);
            TLRPCContacts.TL_setUserGroup req = new TLRPCContacts.TL_setUserGroup();
            req.group_id = 0;
            TLRPCContacts.TL_inputPeerUserChange inputPeer = new TLRPCContacts.TL_inputPeerUserChange();
            inputPeer.access_hash = this.user.access_hash;
            inputPeer.user_id = this.user.id;
            inputPeer.fist_name = this.user.first_name;
            req.users.add(inputPeer);
            final int reqId = connectionsManager.sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.adapter.grouping.-$$Lambda$ArtistViewHolder$-wGYIY3ZkzZ4YM4fI2rrupKGPFE
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.adapter.grouping.-$$Lambda$ArtistViewHolder$v-gpzbQ6MoGHHD-gbKVK7dNMGoo
                        @Override // java.lang.Runnable
                        public final void run() {
                            ArtistViewHolder.lambda$null$0(alertDialog, tL_error, tLObject);
                        }
                    });
                }
            });
            connectionsManager.bindRequestToGuid(reqId, this.adapter.getActivity().getClassGuid());
            alertDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.adapter.grouping.-$$Lambda$ArtistViewHolder$1gMBeTCaZQ8a30PWPMXx7uNhNsQ
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    connectionsManager.cancelRequest(reqId, true);
                }
            });
            this.adapter.getActivity().showDialog(alertDialog);
        }
    }

    static /* synthetic */ void lambda$null$0(AlertDialog alertDialog, TLRPC.TL_error error, TLObject response) {
        alertDialog.dismiss();
        if (error == null) {
            if (!(response instanceof TLRPC.TL_boolTrue)) {
                ToastUtils.show((CharSequence) "移出失败，请稍后重试");
                return;
            }
            return;
        }
        ToastUtils.show((CharSequence) error.text);
    }

    public /* synthetic */ void lambda$new$4$ArtistViewHolder(SwipeLayout swipeLayout, View v) {
        if (!swipeLayout.isExpanded()) {
            if (this.user != null) {
                Bundle bundle = new Bundle();
                bundle.putInt("user_id", this.user.id);
                this.adapter.getActivity().presentFragment(new NewProfileActivity(bundle));
                return;
            }
            return;
        }
        swipeLayout.collapseAll(true);
    }

    public void setUserData(Artist artist, Genre genre, GenreAdapter genreAdapter) {
        this.artist = artist;
        this.genre = genre;
        this.adapter = genreAdapter;
        initData();
    }

    private void initData() {
        SwipeLayout swipeLayout = (SwipeLayout) this.itemView;
        swipeLayout.setSwipeEnabled(this.genre.getGroupId() != 0);
        List<? extends ExpandableGroup> groups = this.adapter.getGroups();
        Genre genre = (Genre) groups.get(groups.size() - 1);
        if (this.genre.getGroupId() == genre.getGroupId()) {
            List<Artist> artists = this.genre.getItems();
            if (this.artist.getUserId() == artists.get(artists.size() - 1).getUserId()) {
                this.itemView.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            }
        } else {
            this.itemView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        }
        TLRPC.User user = MessagesController.getInstance(UserConfig.selectedAccount).getUser(Integer.valueOf(this.artist.getUserId()));
        this.user = user;
        if (user != null) {
            AvatarDrawable avatarDrawable = new AvatarDrawable(this.user);
            this.ivAvatar.setRoundRadius(AndroidUtilities.dp(7.5f));
            this.ivAvatar.setImage(ImageLocation.getForUser(this.user, false), "50_50", avatarDrawable, this.user);
            this.tvName.setText(UserObject.getName(this.user));
            if (this.user.id == UserConfig.getInstance(UserConfig.selectedAccount).getClientUserId() || ((this.user.status != null && this.user.status.expires > ConnectionsManager.getInstance(UserConfig.selectedAccount).getCurrentTime()) || MessagesController.getInstance(UserConfig.selectedAccount).onlinePrivacy.containsKey(Integer.valueOf(this.user.id)))) {
                this.tvStatus.setTextColor(Theme.getColor(Theme.key_color_42B71E));
                this.tvStatus.setText(LocaleController.getString("Online", R.string.Online));
            } else {
                this.tvStatus.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
                this.tvStatus.setText(LocaleController.formatUserStatus(UserConfig.selectedAccount, this.user));
            }
        }
    }
}
