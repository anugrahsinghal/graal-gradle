//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package bug;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.channels.Channel;
import java.nio.channels.UnsupportedAddressTypeException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.gradle.internal.impldep.org.apache.sshd.agent.SshAgentFactory;
import org.gradle.internal.impldep.org.apache.sshd.client.ClientBuilder;
import org.gradle.internal.impldep.org.apache.sshd.client.auth.AuthenticationIdentitiesProvider;
import org.gradle.internal.impldep.org.apache.sshd.client.auth.UserAuthFactory;
import org.gradle.internal.impldep.org.apache.sshd.client.auth.hostbased.HostBasedAuthenticationReporter;
import org.gradle.internal.impldep.org.apache.sshd.client.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.gradle.internal.impldep.org.apache.sshd.client.auth.keyboard.UserInteraction;
import org.gradle.internal.impldep.org.apache.sshd.client.auth.password.PasswordAuthenticationReporter;
import org.gradle.internal.impldep.org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.gradle.internal.impldep.org.apache.sshd.client.auth.password.UserAuthPasswordFactory;
import org.gradle.internal.impldep.org.apache.sshd.client.auth.pubkey.PublicKeyAuthenticationReporter;
import org.gradle.internal.impldep.org.apache.sshd.client.auth.pubkey.UserAuthPublicKey;
import org.gradle.internal.impldep.org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory;
import org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntry;
import org.gradle.internal.impldep.org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentity;
import org.gradle.internal.impldep.org.apache.sshd.client.config.keys.ClientIdentityLoader;
import org.gradle.internal.impldep.org.apache.sshd.client.config.keys.DefaultClientIdentitiesWatcher;
import org.gradle.internal.impldep.org.apache.sshd.client.future.AuthFuture;
import org.gradle.internal.impldep.org.apache.sshd.client.future.ConnectFuture;
import org.gradle.internal.impldep.org.apache.sshd.client.future.DefaultConnectFuture;
import org.gradle.internal.impldep.org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.gradle.internal.impldep.org.apache.sshd.client.session.AbstractClientSession;
import org.gradle.internal.impldep.org.apache.sshd.client.session.ClientConnectionServiceFactory;
import org.gradle.internal.impldep.org.apache.sshd.client.session.ClientProxyConnector;
import org.gradle.internal.impldep.org.apache.sshd.client.session.ClientSession;
import org.gradle.internal.impldep.org.apache.sshd.client.session.ClientUserAuthServiceFactory;
import org.gradle.internal.impldep.org.apache.sshd.client.session.SessionFactory;
import org.gradle.internal.impldep.org.apache.sshd.client.session.forward.ExplicitPortForwardingTracker;
import org.gradle.internal.impldep.org.apache.sshd.client.simple.AbstractSimpleClientSessionCreator;
import org.gradle.internal.impldep.org.apache.sshd.client.simple.SimpleClient;
import org.gradle.internal.impldep.org.apache.sshd.common.AttributeRepository;
import org.gradle.internal.impldep.org.apache.sshd.common.Closeable;
import org.gradle.internal.impldep.org.apache.sshd.common.Factory;
import org.gradle.internal.impldep.org.apache.sshd.common.NamedResource;
import org.gradle.internal.impldep.org.apache.sshd.common.ServiceFactory;
import org.gradle.internal.impldep.org.apache.sshd.common.channel.ChannelFactory;
import org.gradle.internal.impldep.org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.gradle.internal.impldep.org.apache.sshd.common.config.keys.FilePasswordProviderManager;
import org.gradle.internal.impldep.org.apache.sshd.common.config.keys.KeyUtils;
import org.gradle.internal.impldep.org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.gradle.internal.impldep.org.apache.sshd.common.future.CancelFuture;
import org.gradle.internal.impldep.org.apache.sshd.common.future.CancelOption;
import org.gradle.internal.impldep.org.apache.sshd.common.future.Cancellable;
import org.gradle.internal.impldep.org.apache.sshd.common.future.SshFutureListener;
import org.gradle.internal.impldep.org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.gradle.internal.impldep.org.apache.sshd.common.io.IoConnectFuture;
import org.gradle.internal.impldep.org.apache.sshd.common.io.IoConnector;
import org.gradle.internal.impldep.org.apache.sshd.common.io.IoSession;
import org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.AbstractResourceKeyPairProvider;
import org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.gradle.internal.impldep.org.apache.sshd.common.keyprovider.MultiKeyIdentityProvider;
import org.gradle.internal.impldep.org.apache.sshd.common.session.helpers.AbstractSession;
import org.gradle.internal.impldep.org.apache.sshd.common.util.ExceptionUtils;
import org.gradle.internal.impldep.org.apache.sshd.common.util.GenericUtils;
import org.gradle.internal.impldep.org.apache.sshd.common.util.ValidateUtils;
import org.gradle.internal.impldep.org.apache.sshd.common.util.functors.UnaryEquator;
import org.gradle.internal.impldep.org.apache.sshd.common.util.io.resource.PathResource;
import org.gradle.internal.impldep.org.apache.sshd.common.util.net.SshdSocketAddress;
import org.gradle.internal.impldep.org.apache.sshd.core.CoreModuleProperties;

public class SshClient extends AbstractFactoryManager implements ClientFactoryManager, Closeable {
  public static final Factory<SshClient> DEFAULT_SSH_CLIENT_FACTORY = SshClient::new;
  public static final List<UserAuthFactory> DEFAULT_USER_AUTH_FACTORIES;
  public static final List<ServiceFactory> DEFAULT_SERVICE_FACTORIES;
  protected IoConnector connector;
  protected SessionFactory sessionFactory;
  protected List<UserAuthFactory> userAuthFactories;
  private ClientProxyConnector proxyConnector;
  private ServerKeyVerifier serverKeyVerifier;
  private HostConfigEntryResolver hostConfigEntryResolver;
  private ClientIdentityLoader clientIdentityLoader;
  private KeyIdentityProvider keyIdentityProvider;
  private PublicKeyAuthenticationReporter publicKeyAuthenticationReporter;
  private FilePasswordProvider filePasswordProvider;
  private PasswordIdentityProvider passwordIdentityProvider;
  private PasswordAuthenticationReporter passwordAuthenticationReporter;
  private HostBasedAuthenticationReporter hostBasedAuthenticationReporter;
  private UserInteraction userInteraction;
  private final List<Object> identities = new CopyOnWriteArrayList();
  private final AuthenticationIdentitiesProvider identitiesProvider;
  private final AtomicBoolean started = new AtomicBoolean(false);

  public SshClient() {
    this.identitiesProvider = AuthenticationIdentitiesProvider.wrapIdentities(this.identities);
  }

  public SessionFactory getSessionFactory() {
    return this.sessionFactory;
  }

  public void setSessionFactory(SessionFactory sessionFactory) {
    this.sessionFactory = sessionFactory;
  }

  public ClientProxyConnector getClientProxyConnector() {
    return this.proxyConnector;
  }

  public void setClientProxyConnector(ClientProxyConnector proxyConnector) {
    this.proxyConnector = proxyConnector;
  }

  public ServerKeyVerifier getServerKeyVerifier() {
    return this.serverKeyVerifier;
  }

  public void setServerKeyVerifier(ServerKeyVerifier serverKeyVerifier) {
    this.serverKeyVerifier = (ServerKeyVerifier)Objects.requireNonNull(serverKeyVerifier, "No server key verifier");
  }

  public HostConfigEntryResolver getHostConfigEntryResolver() {
    return this.hostConfigEntryResolver;
  }

  public void setHostConfigEntryResolver(HostConfigEntryResolver resolver) {
    this.hostConfigEntryResolver = (HostConfigEntryResolver)Objects.requireNonNull(resolver, "No host configuration entry resolver");
  }

  public FilePasswordProvider getFilePasswordProvider() {
    return this.filePasswordProvider;
  }

  public void setFilePasswordProvider(FilePasswordProvider provider) {
    this.filePasswordProvider = (FilePasswordProvider)Objects.requireNonNull(provider, "No file password provider");
  }

  public ClientIdentityLoader getClientIdentityLoader() {
    return this.clientIdentityLoader;
  }

  public void setClientIdentityLoader(ClientIdentityLoader loader) {
    this.clientIdentityLoader = (ClientIdentityLoader)Objects.requireNonNull(loader, "No client identity loader");
  }

  public UserInteraction getUserInteraction() {
    return this.userInteraction;
  }

  public void setUserInteraction(UserInteraction userInteraction) {
    this.userInteraction = userInteraction;
  }

  public PasswordAuthenticationReporter getPasswordAuthenticationReporter() {
    return this.passwordAuthenticationReporter;
  }

  public void setPasswordAuthenticationReporter(PasswordAuthenticationReporter reporter) {
    this.passwordAuthenticationReporter = reporter;
  }

  public HostBasedAuthenticationReporter getHostBasedAuthenticationReporter() {
    return this.hostBasedAuthenticationReporter;
  }

  public void setHostBasedAuthenticationReporter(HostBasedAuthenticationReporter reporter) {
    this.hostBasedAuthenticationReporter = reporter;
  }

  public List<UserAuthFactory> getUserAuthFactories() {
    return this.userAuthFactories;
  }

  public void setUserAuthFactories(List<UserAuthFactory> userAuthFactories) {
    this.userAuthFactories = (List)ValidateUtils.checkNotNullAndNotEmpty(userAuthFactories, "No user auth factories", new Object[0]);
  }

  public AuthenticationIdentitiesProvider getRegisteredIdentities() {
    return this.identitiesProvider;
  }

  public PasswordIdentityProvider getPasswordIdentityProvider() {
    return this.passwordIdentityProvider;
  }

  public void setPasswordIdentityProvider(PasswordIdentityProvider provider) {
    this.passwordIdentityProvider = provider;
  }

  public void addPasswordIdentity(String password) {
    ValidateUtils.checkTrue(password != null && !password.isEmpty(), "No password provided");
    this.identities.add(password);
    if (this.log.isDebugEnabled()) {
      this.log.debug("addPasswordIdentity({}) {}", this, KeyUtils.getFingerPrint(password));
    }

  }

  public String removePasswordIdentity(String password) {
    if (GenericUtils.isEmpty(password)) {
      return null;
    } else {
      int index = AuthenticationIdentitiesProvider.findIdentityIndex(this.identities, AuthenticationIdentitiesProvider.PASSWORD_IDENTITY_COMPARATOR, password);
      return index >= 0 ? (String)this.identities.remove(index) : null;
    }
  }

  public void addPublicKeyIdentity(KeyPair kp) {
    Objects.requireNonNull(kp, "No key-pair to add");
    Objects.requireNonNull(kp.getPublic(), "No public key");
    Objects.requireNonNull(kp.getPrivate(), "No private key");
    this.identities.add(kp);
    if (this.log.isDebugEnabled()) {
      this.log.debug("addPublicKeyIdentity({}) {}", this, KeyUtils.getFingerPrint(kp.getPublic()));
    }

  }

  public KeyPair removePublicKeyIdentity(KeyPair kp) {
    if (kp == null) {
      return null;
    } else {
      int index = AuthenticationIdentitiesProvider.findIdentityIndex(this.identities, AuthenticationIdentitiesProvider.KEYPAIR_IDENTITY_COMPARATOR, kp);
      return index >= 0 ? (KeyPair)this.identities.remove(index) : null;
    }
  }

  public KeyIdentityProvider getKeyIdentityProvider() {
    return this.keyIdentityProvider;
  }

  public void setKeyIdentityProvider(KeyIdentityProvider keyIdentityProvider) {
    this.keyIdentityProvider = keyIdentityProvider;
  }

  public PublicKeyAuthenticationReporter getPublicKeyAuthenticationReporter() {
    return this.publicKeyAuthenticationReporter;
  }

  public void setPublicKeyAuthenticationReporter(PublicKeyAuthenticationReporter reporter) {
    this.publicKeyAuthenticationReporter = reporter;
  }

  protected void checkConfig() {
    super.checkConfig();
    Objects.requireNonNull(this.getForwarderFactory(), "ForwarderFactory not set");
    Objects.requireNonNull(this.getServerKeyVerifier(), "ServerKeyVerifier not set");
    Objects.requireNonNull(this.getHostConfigEntryResolver(), "HostConfigEntryResolver not set");
    Objects.requireNonNull(this.getClientIdentityLoader(), "ClientIdentityLoader not set");
    Objects.requireNonNull(this.getFilePasswordProvider(), "FilePasswordProvider not set");
    KeyIdentityProvider defaultIdentities = this.getKeyIdentityProvider();
    if (defaultIdentities == null) {
      KeyIdentityProvider idsWatcher = new DefaultClientIdentitiesWatcher(this::getClientIdentityLoader, this::getFilePasswordProvider);
      this.setKeyIdentityProvider(idsWatcher);
    }

    SshAgentFactory agentFactory = this.getAgentFactory();
    if (agentFactory != null) {
      List<ChannelFactory> forwarders = agentFactory.getChannelForwardingFactories(this);
      if (!GenericUtils.isEmpty(forwarders)) {
        List<? extends ChannelFactory> factories = this.getChannelFactories();
        Object factories;
        if (GenericUtils.isEmpty(factories)) {
          factories = forwarders;
        } else {
          List<ChannelFactory> factories2 = new ArrayList(factories.size() + forwarders.size());
          factories2.addAll(factories);
          factories2.addAll(forwarders);
          factories = factories2;
        }

        this.setChannelFactories((List)factories);
      }
    }

    if (GenericUtils.isEmpty(this.getServiceFactories())) {
      this.setServiceFactories(DEFAULT_SERVICE_FACTORIES);
    }

    if (GenericUtils.isEmpty(this.getUserAuthFactories())) {
      this.setUserAuthFactories(DEFAULT_USER_AUTH_FACTORIES);
    }

  }

  public boolean isStarted() {
    return this.started.get();
  }

  public void start() {
    if (this.isClosed()) {
      throw new IllegalStateException("Can not start the client again");
    } else if (!this.isStarted()) {
      this.checkConfig();
      if (this.sessionFactory == null) {
        this.sessionFactory = this.createSessionFactory();
      }

      this.setupSessionTimeout(this.sessionFactory);
      this.connector = this.createConnector();
      this.started.set(true);
    }
  }

  public void stop() {
    if (this.started.getAndSet(false)) {
      try {
        Duration maxWait = (Duration)CoreModuleProperties.STOP_WAIT_TIME.getRequired(this);
        boolean successful = this.close(true).await(maxWait, new CancelOption[0]);
        if (!successful) {
          throw new SocketTimeoutException("Failed to receive closure confirmation within " + maxWait + " millis");
        }
      } catch (IOException var6) {
        IOException e = var6;
        this.warn("{} while stopping client: {}", e.getClass().getSimpleName(), e.getMessage(), e);
      } finally {
        this.clearAttributes();
      }

    }
  }

  public void open() throws IOException {
    this.start();
  }

  protected Closeable getInnerCloseable() {
    Object closeId = this.toString();
    return this.builder().run(closeId, () -> {
      this.removeSessionTimeout(this.sessionFactory);
    }).sequential(new Closeable[]{this.connector, this.ioServiceFactory}).run(closeId, () -> {
      this.connector = null;
      this.ioServiceFactory = null;
      if (this.shutdownExecutor && this.executor != null && !this.executor.isShutdown()) {
        try {
          this.executor.shutdownNow();
        } finally {
          this.executor = null;
        }
      }

    }).build();
  }

  public ConnectFuture connect(String uriStr) throws IOException {
    Objects.requireNonNull(uriStr, "No uri address");
    URI uri = URI.create(uriStr.contains("//") ? uriStr : "ssh://" + uriStr);
    if (GenericUtils.isNotEmpty(uri.getScheme()) && !"ssh".equals(uri.getScheme())) {
      throw new IllegalArgumentException("Unsupported scheme for uri: " + uri);
    } else {
      String host = uri.getHost();
      int port = uri.getPort();
      String userInfo = uri.getUserInfo();
      return this.connect(userInfo, host, port);
    }
  }

  public ConnectFuture connect(String username, SocketAddress targetAddress, AttributeRepository context, SocketAddress localAddress) throws IOException {
    Objects.requireNonNull(targetAddress, "No target address");
    if (!(targetAddress instanceof InetSocketAddress)) {
      throw new UnsupportedAddressTypeException();
    } else {
      InetSocketAddress inetAddress = (InetSocketAddress)targetAddress;
      String host = ValidateUtils.checkNotNullAndNotEmpty(inetAddress.getHostString(), "No host");
      int port = inetAddress.getPort();
      ValidateUtils.checkTrue(port > 0, "Invalid port: %d", (long)port);
      return this.connect(username, host, port, context, localAddress);
    }
  }

  public ConnectFuture connect(String username, String host, int port, AttributeRepository context, SocketAddress localAddress) throws IOException {
    HostConfigEntry entry = this.resolveHost(username, host, port, context, localAddress);
    return this.connect(entry, context, localAddress);
  }

  public ConnectFuture connect(HostConfigEntry hostConfig, AttributeRepository context, SocketAddress localAddress) throws IOException {
    List<HostConfigEntry> jumps = this.parseProxyJumps(hostConfig.getProxyJump(), context);
    return this.doConnect(hostConfig, jumps, context, localAddress);
  }

  protected ConnectFuture doConnect(HostConfigEntry hostConfig, List<HostConfigEntry> jumps, AttributeRepository context, SocketAddress localAddress) throws IOException {
    Objects.requireNonNull(hostConfig, "No host configuration");
    String host = ValidateUtils.checkNotNullAndNotEmpty(hostConfig.getHostName(), "No target host");
    int port = hostConfig.getPort();
    ValidateUtils.checkTrue(port > 0, "Invalid port: %d", (long)port);
    Collection<String> hostIds = hostConfig.getIdentities();
    Collection<PathResource> idFiles = (Collection)GenericUtils.stream(hostIds).map((x$0) -> {
      return Paths.get(x$0);
    }).map(PathResource::new).collect(Collectors.toCollection(() -> {
      return new ArrayList(hostIds.size());
    }));
    KeyIdentityProvider keys = this.preloadClientIdentities(idFiles);
    String username = hostConfig.getUsername();
    InetSocketAddress targetAddress = new InetSocketAddress(hostConfig.getHostName(), hostConfig.getPort());
    if (GenericUtils.isNotEmpty(jumps)) {
      ConnectFuture connectFuture = new DefaultConnectFuture(username + "@" + targetAddress, (Object)null);
      HostConfigEntry jump = (HostConfigEntry)jumps.remove(0);
      ConnectFuture f1 = this.doConnect(jump, jumps, context, (SocketAddress)null);
      AtomicReference<Cancellable> toCancel = new AtomicReference(f1);
      connectFuture.addListener((c) -> {
        if (c.isCanceled()) {
          Cancellable inner = (Cancellable)toCancel.get();
          if (inner != null) {
            CancelFuture cancellation = inner.cancel();
            if (cancellation != null) {
              cancellation.addListener((cf) -> {
                if (cf.isDone()) {
                  c.getCancellation().setCanceled();
                }

              });
            }
          }
        }
      });
      f1.addListener((f2) -> {
        if (f2.isConnected()) {
          ClientSession proxySession = f2.getClientSession();

          try {
            if (connectFuture.isCanceled()) {
              proxySession.close(true);
            }

            AuthFuture auth = proxySession.auth();
            toCancel.set(auth);
            auth.addListener((f3) -> {
              if (f3.isSuccess()) {
                try {
                  SshdSocketAddress address = new SshdSocketAddress(hostConfig.getHostName(), hostConfig.getPort());
                  ExplicitPortForwardingTracker tracker = proxySession.createLocalPortForwardingTracker(SshdSocketAddress.LOCALHOST_ADDRESS, address);
                  SshdSocketAddress bound = tracker.getBoundAddress();
                  ConnectFuture f4 = this.doConnect(hostConfig.getUsername(), bound.toInetSocketAddress(), context, localAddress, keys, hostConfig);
                  toCancel.set(f4);
                  if (connectFuture.isCanceled()) {
                    f4.cancel();
                  }

                  f4.addListener((f5) -> {
                    if (f5.isConnected()) {
                      ClientSession clientSession = f5.getClientSession();
                      clientSession.setAttribute(TARGET_SERVER, address);
                      connectFuture.setSession(clientSession);
                      proxySession.addCloseFutureListener((f6) -> {
                        clientSession.close(true);
                      });
                      clientSession.addCloseFutureListener((f6) -> {
                        proxySession.close(true);
                      });
                    } else {
                      proxySession.close(true);
                      connectFuture.setException(f5.getException());
                    }

                  });
                } catch (IOException var13) {
                  IOException e = var13;
                  proxySession.close(true);
                  connectFuture.setException(e);
                }
              } else {
                proxySession.close(true);
                connectFuture.setException(f3.getException());
              }

            });
          } catch (IOException var10) {
            IOException e = var10;
            proxySession.close(true);
            connectFuture.setException(e);
          }
        } else {
          connectFuture.setException(f2.getException());
        }

      });
      return connectFuture;
    } else {
      return this.doConnect(hostConfig.getUsername(), new InetSocketAddress(host, port), context, localAddress, keys, hostConfig);
    }
  }

  protected ConnectFuture doConnect(String username, SocketAddress targetAddress, AttributeRepository context, SocketAddress localAddress, KeyIdentityProvider identities, HostConfigEntry hostConfig) throws IOException {
    if (this.connector == null) {
      throw new IllegalStateException("SshClient not started. Please call start() method before connecting to a server");
    } else {
      ConnectFuture connectFuture = new DefaultConnectFuture(username + "@" + targetAddress, (Object)null);
      SshFutureListener<IoConnectFuture> listener = this.createConnectCompletionListener(connectFuture, username, targetAddress, identities, hostConfig);
      IoConnectFuture connectingFuture = this.connector.connect(targetAddress, context, localAddress);
      connectFuture.addListener((c) -> {
        if (c.isCanceled()) {
          connectingFuture.cancel();
        }

      });
      connectingFuture.addListener(listener);
      return connectFuture;
    }
  }

  protected List<HostConfigEntry> parseProxyJumps(String proxyJump, AttributeRepository context) throws IOException {
    List<HostConfigEntry> jumps = new ArrayList();
    String[] var4 = GenericUtils.split(proxyJump, ',');
    int var5 = var4.length;

    for(int var6 = 0; var6 < var5; ++var6) {
      String jump = var4[var6];
      String j = jump.trim();
      URI uri = URI.create(j.contains("//") ? j : "ssh://" + j);
      if (GenericUtils.isNotEmpty(uri.getScheme()) && !"ssh".equals(uri.getScheme())) {
        throw new IllegalArgumentException("Unsupported scheme for proxy jump: " + jump);
      }

      String host = uri.getHost();
      int port = uri.getPort();
      String userInfo = uri.getUserInfo();
      HostConfigEntry entry = this.resolveHost(userInfo, host, port, context, (SocketAddress)null);
      jumps.add(entry);
    }

    return jumps;
  }

  protected HostConfigEntry resolveHost(String username, String host, int port, AttributeRepository context, SocketAddress localAddress) throws IOException {
    HostConfigEntryResolver resolver = this.getHostConfigEntryResolver();
    HostConfigEntry entry = resolver.resolveEffectiveHost(host, port, localAddress, username, (String)null, context);
    if (entry == null) {
      if (this.log.isDebugEnabled()) {
        this.log.debug("connect({}@{}:{}) no overrides", new Object[]{username, host, port});
      }

      if (SshdSocketAddress.isIPv6Address(host)) {
        entry = new HostConfigEntry("", host, port, username, (String)null);
      } else {
        entry = new HostConfigEntry(host, host, port, username, (String)null);
      }
    } else if (this.log.isDebugEnabled()) {
      this.log.debug("connect({}@{}:{}) effective: {}", new Object[]{username, host, port, entry});
    }

    return entry;
  }

  protected KeyIdentityProvider preloadClientIdentities(Collection<? extends NamedResource> locations) throws IOException {
    return GenericUtils.isEmpty(locations) ? KeyIdentityProvider.EMPTY_KEYS_PROVIDER : ClientIdentityLoader.asKeyIdentityProvider((ClientIdentityLoader)Objects.requireNonNull(this.getClientIdentityLoader(), "No ClientIdentityLoader"), locations, this.getFilePasswordProvider(), (Boolean)CoreModuleProperties.IGNORE_INVALID_IDENTITIES.getRequired(this));
  }

  protected SshFutureListener<IoConnectFuture> createConnectCompletionListener(final ConnectFuture connectFuture, final String username, final SocketAddress address, final KeyIdentityProvider identities, final HostConfigEntry hostConfig) {
    return new SshFutureListener<IoConnectFuture>() {
      public void operationComplete(IoConnectFuture future) {
        if (future.isCanceled()) {
          CancelFuture cancellation = connectFuture.cancel();
          if (cancellation != null) {
            future.getCancellation().addListener((f) -> {
              cancellation.setCanceled(f.getBackTrace());
            });
          }

        } else {
          Throwable t = future.getException();
          if (t != null) {
            if (SshClient.this.log.isDebugEnabled()) {
              SshClient.this.log.debug("operationComplete({}@{}) failed ({}): {}", new Object[]{username, address, t.getClass().getSimpleName(), t.getMessage()});
            }

            connectFuture.setException(t);
          } else {
            IoSession ioSession = future.getSession();

            try {
              SshClient.this.onConnectOperationComplete(ioSession, connectFuture, username, address, identities, hostConfig);
            } catch (GeneralSecurityException | RuntimeException | IOException var5) {
              Exception e = var5;
              SshClient.this.warn("operationComplete({}@{}) failed ({}) to signal completion of session={}: {}", username, address, e.getClass().getSimpleName(), ioSession, ((Exception)e).getMessage(), e);
              connectFuture.setException(e);
              ioSession.close(true);
            }
          }

        }
      }

      public String toString() {
        return "ConnectCompletionListener[" + username + "@" + address + "]";
      }
    };
  }

  protected void onConnectOperationComplete(IoSession ioSession, ConnectFuture connectFuture, String username, SocketAddress address, KeyIdentityProvider identities, HostConfigEntry hostConfig) throws IOException, GeneralSecurityException {
    AbstractClientSession session = (AbstractClientSession)AbstractSession.getSession(ioSession);
    session.setUsername(username);
    session.setConnectAddress(address);
    boolean useDefaultIdentities = !hostConfig.isIdentitiesOnly();
    session.setAttribute(UserAuthPublicKey.USE_DEFAULT_IDENTITIES, useDefaultIdentities);
    String identityAgent = hostConfig.getProperty("IdentityAgent");
    session.setAttribute(UserAuthPublicKey.IDENTITY_AGENT, identityAgent == null ? "" : identityAgent);
    if (useDefaultIdentities) {
      this.setupDefaultSessionIdentities(session, identities);
    } else if (identities == null) {
      session.setKeyIdentityProvider(KeyIdentityProvider.EMPTY_KEYS_PROVIDER);
    } else {
      session.setKeyIdentityProvider(this.ensureFilePasswordProvider(identities));
    }

    connectFuture.setSession(session);
    if (session != connectFuture.getSession()) {
      boolean var14 = false;

      try {
        var14 = true;
        session.close(true);
        var14 = false;
      } finally {
        if (var14) {
          CancelFuture cancellation = connectFuture.cancel();
          if (cancellation != null) {
            cancellation.setCanceled();
          }

        }
      }

      CancelFuture cancellation = connectFuture.cancel();
      if (cancellation != null) {
        cancellation.setCanceled();
      }
    }

  }

  protected KeyIdentityProvider ensureFilePasswordProvider(KeyIdentityProvider identities) {
    FilePasswordProvider passwordProvider;
    if (identities instanceof AbstractResourceKeyPairProvider) {
      AbstractResourceKeyPairProvider<?> keyProvider = (AbstractResourceKeyPairProvider)identities;
      if (keyProvider.getPasswordFinder() == null) {
        passwordProvider = this.getFilePasswordProvider();
        if (passwordProvider != null) {
          keyProvider.setPasswordFinder(passwordProvider);
        }
      }
    } else if (identities instanceof FilePasswordProviderManager) {
      FilePasswordProviderManager keyProvider = (FilePasswordProviderManager)identities;
      if (keyProvider.getFilePasswordProvider() == null) {
        passwordProvider = this.getFilePasswordProvider();
        if (passwordProvider != null) {
          keyProvider.setFilePasswordProvider(passwordProvider);
        }
      }
    } else if (identities instanceof MultiKeyIdentityProvider) {
      MultiKeyIdentityProvider multiProvider = (MultiKeyIdentityProvider)identities;
      multiProvider.getProviders().forEach(this::ensureFilePasswordProvider);
    }

    return identities;
  }

  protected void setupDefaultSessionIdentities(ClientSession session, KeyIdentityProvider extraIdentities) throws IOException, GeneralSecurityException {
    boolean debugEnabled = this.log.isDebugEnabled();
    KeyIdentityProvider kpSession = session.getKeyIdentityProvider();
    KeyIdentityProvider kpClient = this.getKeyIdentityProvider();
    if (UnaryEquator.isSameReference(kpSession, kpClient) && debugEnabled) {
      this.log.debug("setupDefaultSessionIdentities({}) key identity provider override in session listener", session);
    }

    KeyIdentityProvider kpEffective = KeyIdentityProvider.resolveKeyIdentityProvider(extraIdentities, kpSession);
    kpEffective = this.ensureFilePasswordProvider(kpEffective);
    if (!UnaryEquator.isSameReference(kpSession, kpEffective)) {
      if (debugEnabled) {
        this.log.debug("setupDefaultSessionIdentities({}) key identity provider enhanced", session);
      }

      session.setKeyIdentityProvider(kpEffective);
    }

    PasswordIdentityProvider passSession = session.getPasswordIdentityProvider();
    PasswordIdentityProvider passClient = this.getPasswordIdentityProvider();
    if (!UnaryEquator.isSameReference(passSession, passClient) && debugEnabled) {
      this.log.debug("setupDefaultSessionIdentities({}) password provider override", session);
    }

    AuthenticationIdentitiesProvider idsClient = this.getRegisteredIdentities();
    boolean traceEnabled = this.log.isTraceEnabled();
    Iterator<?> iter = GenericUtils.iteratorOf(idsClient == null ? null : idsClient.loadIdentities(session));

    while(iter.hasNext()) {
      Object id = iter.next();
      if (id instanceof String) {
        if (traceEnabled) {
          this.log.trace("setupDefaultSessionIdentities({}) add password fingerprint={}", session, KeyUtils.getFingerPrint(id.toString()));
        }

        session.addPasswordIdentity((String)id);
      } else if (id instanceof KeyPair) {
        KeyPair kp = (KeyPair)id;
        if (traceEnabled) {
          this.log.trace("setupDefaultSessionIdentities({}) add identity type={}, fingerprint={}", new Object[]{session, KeyUtils.getKeyType(kp), KeyUtils.getFingerPrint(kp.getPublic())});
        }

        session.addPublicKeyIdentity(kp);
      } else if (debugEnabled) {
        this.log.debug("setupDefaultSessionIdentities({}) ignored identity={}", session, id);
      }
    }

  }

  protected IoConnector createConnector() {
    return this.getIoServiceFactory().createConnector(this.getSessionFactory());
  }

  protected SessionFactory createSessionFactory() {
    return new SessionFactory(this);
  }

  public String toString() {
    return this.getClass().getSimpleName() + "[" + Integer.toHexString(this.hashCode()) + "]";
  }

  public static SimpleClient setUpDefaultSimpleClient() {
    SshClient client = setUpDefaultClient();
    client.start();
    return wrapAsSimpleClient(client);
  }

  public static SimpleClient wrapAsSimpleClient(final SshClient client) {
    Objects.requireNonNull(client, "No client instance");
    Channel channel = new Channel() {
      public boolean isOpen() {
        return client.isOpen();
      }

      public void close() throws IOException {
        Exception err = null;

        Exception e;
        try {
          client.close();
        } catch (Exception var4) {
          e = var4;
          err = (Exception)ExceptionUtils.accumulateException(err, e);
        }

        try {
          client.stop();
        } catch (Exception var3) {
          e = var3;
          err = (Exception)ExceptionUtils.accumulateException(err, e);
        }

        if (err != null) {
          if (err instanceof IOException) {
            throw (IOException)err;
          } else {
            throw new IOException(err);
          }
        }
      }
    };
    return AbstractSimpleClientSessionCreator.wrap(client, channel);
  }

  public static SshClient setUpDefaultClient() {
    ClientBuilder builder = ClientBuilder.builder();
    return (SshClient)builder.build();
  }

  public static <C extends SshClient> C setKeyPairProvider(C client, boolean strict, boolean supportedOnly, FilePasswordProvider provider, LinkOption... options) throws IOException, GeneralSecurityException {
    return setKeyPairProvider(client, PublicKeyEntry.getDefaultKeysFolderPath(), strict, supportedOnly, provider, options);
  }

  public static <C extends SshClient> C setKeyPairProvider(C client, Path dir, boolean strict, boolean supportedOnly, FilePasswordProvider provider, LinkOption... options) throws IOException, GeneralSecurityException {
    KeyIdentityProvider kpp = ClientIdentity.loadDefaultKeyPairProvider(dir, strict, supportedOnly, provider, options);
    if (kpp != null) {
      client.setKeyIdentityProvider(kpp);
    }

    return client;
  }

  static {
    DEFAULT_USER_AUTH_FACTORIES = Collections.unmodifiableList(Arrays.asList(UserAuthPublicKeyFactory.INSTANCE, UserAuthKeyboardInteractiveFactory.INSTANCE, UserAuthPasswordFactory.INSTANCE));
    DEFAULT_SERVICE_FACTORIES = Collections.unmodifiableList(Arrays.asList(ClientUserAuthServiceFactory.INSTANCE, ClientConnectionServiceFactory.INSTANCE));
  }
}
