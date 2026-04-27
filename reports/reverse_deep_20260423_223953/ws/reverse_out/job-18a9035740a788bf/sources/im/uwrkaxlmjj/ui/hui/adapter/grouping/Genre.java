package im.uwrkaxlmjj.ui.hui.adapter.grouping;

import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.expand.models.ExpandableGroup;
import java.util.List;

/* JADX INFO: loaded from: classes5.dex */
public class Genre extends ExpandableGroup<Artist> {
    private int groupId;
    private int orderId;

    public Genre(TLRPCContacts.TL_contactsGroupInfo groupInfo, List<Artist> items) {
        super(groupInfo.title, items);
        this.groupId = groupInfo.group_id;
        this.orderId = groupInfo.order_id;
    }

    public int getGroupId() {
        return this.groupId;
    }

    public int getOrderId() {
        return this.orderId;
    }

    public int getOnlineCount() {
        int onlineCount = 0;
        MessagesController messagesController = MessagesController.getInstance(UserConfig.selectedAccount);
        for (Artist artist : getItems()) {
            TLRPC.User user = messagesController.getUser(Integer.valueOf(artist.getUserId()));
            if (user.id == UserConfig.getInstance(UserConfig.selectedAccount).getClientUserId() || ((user.status != null && user.status.expires > ConnectionsManager.getInstance(UserConfig.selectedAccount).getCurrentTime()) || MessagesController.getInstance(UserConfig.selectedAccount).onlinePrivacy.containsKey(Integer.valueOf(user.id)))) {
                onlineCount++;
            }
        }
        return onlineCount;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Genre)) {
            return false;
        }
        Genre genre = (Genre) o;
        return this.groupId == genre.getGroupId();
    }

    public int hashCode() {
        int result = getTitle() != null ? getTitle().hashCode() : 0;
        return result * 31;
    }
}
