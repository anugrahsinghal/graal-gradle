package bug;

import org.gradle.internal.impldep.org.apache.sshd.common.util.GenericUtils;
import org.gradle.internal.impldep.org.apache.sshd.sftp.client.SftpClientFactory;
import org.gradle.internal.impldep.org.apache.sshd.sftp.client.SftpErrorDataHandler;
import org.gradle.internal.impldep.org.apache.sshd.sftp.client.SftpVersionSelector;
import org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystem;
import org.gradle.internal.impldep.org.apache.sshd.sftp.client.fs.SftpFileSystemClientSessionInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.util.Collections;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;

public class SftpFileSystemProvider extends FileSystemProvider {
  public static final String VERSION_PARAM = "version";
  public static final Set<Class<? extends FileAttributeView>> UNIVERSAL_SUPPORTED_VIEWS = Collections.unmodifiableSet(GenericUtils.asSet(new Class[]{PosixFileAttributeView.class, FileOwnerAttributeView.class, BasicFileAttributeView.class}));
  protected final Logger log;
  private final SshClient clientInstance;
  private final SftpClientFactory factory;
  private final SftpVersionSelector versionSelector;
  private final SftpErrorDataHandler errorDataHandler;
  private final NavigableMap<String, SftpFileSystem> fileSystems;
  private SftpFileSystemClientSessionInitializer fsSessionInitializer;

  public SftpFileSystemProvider(SshClient client, SftpClientFactory factory, SftpVersionSelector selector, SftpErrorDataHandler errorDataHandler) {
    this.fileSystems = new TreeMap(String.CASE_INSENSITIVE_ORDER);
    this.fsSessionInitializer = SftpFileSystemClientSessionInitializer.DEFAULT;
    this.log = LoggerFactory.getLogger(this.getClass());
    this.factory = factory;
    this.versionSelector = selector;
    this.errorDataHandler = errorDataHandler;
    if (client == null) {
      client = SshClient.setUpDefaultClient();
      client.start();
    }

    this.clientInstance = client;
  }

}
