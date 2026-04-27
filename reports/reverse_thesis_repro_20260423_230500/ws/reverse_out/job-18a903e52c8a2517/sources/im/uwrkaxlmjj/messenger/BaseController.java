package im.uwrkaxlmjj.messenger;

import im.uwrkaxlmjj.tgnet.ConnectionsManager;

/* JADX INFO: loaded from: classes2.dex */
public class BaseController {
    protected int currentAccount;
    private AccountInstance parentAccountInstance;

    public BaseController(int num) {
        this.parentAccountInstance = AccountInstance.getInstance(num);
        this.currentAccount = num;
    }

    protected AccountInstance getAccountInstance() {
        return this.parentAccountInstance;
    }

    protected MessagesController getMessagesController() {
        return this.parentAccountInstance.getMessagesController();
    }

    protected ContactsController getContactsController() {
        return this.parentAccountInstance.getContactsController();
    }

    protected MediaDataController getMediaDataController() {
        return this.parentAccountInstance.getMediaDataController();
    }

    protected ConnectionsManager getConnectionsManager() {
        return this.parentAccountInstance.getConnectionsManager();
    }

    protected LocationController getLocationController() {
        return this.parentAccountInstance.getLocationController();
    }

    protected NotificationsController getNotificationsController() {
        return this.parentAccountInstance.getNotificationsController();
    }

    protected NotificationCenter getNotificationCenter() {
        return this.parentAccountInstance.getNotificationCenter();
    }

    protected UserConfig getUserConfig() {
        return this.parentAccountInstance.getUserConfig();
    }

    protected MessagesStorage getMessagesStorage() {
        return this.parentAccountInstance.getMessagesStorage();
    }

    protected DownloadController getDownloadController() {
        return this.parentAccountInstance.getDownloadController();
    }

    protected SendMessagesHelper getSendMessagesHelper() {
        return this.parentAccountInstance.getSendMessagesHelper();
    }

    protected SecretChatHelper getSecretChatHelper() {
        return this.parentAccountInstance.getSecretChatHelper();
    }

    protected StatsController getStatsController() {
        return this.parentAccountInstance.getStatsController();
    }

    protected FileLoader getFileLoader() {
        return this.parentAccountInstance.getFileLoader();
    }

    protected FileRefController getFileRefController() {
        return this.parentAccountInstance.getFileRefController();
    }
}
