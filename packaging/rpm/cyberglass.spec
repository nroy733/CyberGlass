Name:           cyberglass
Version:        %{version_override}
Release:        1%{?dist}
Summary:        Self-hosted security analytics and event monitoring platform
License:        Apache-2.0
BuildArch:      %{_target_cpu}
Source0:        cyberglass-bundle.tar.gz
Source1:        cyberglass.service
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
CyberGlass is a self-hosted security analytics platform for collecting,
searching, and detecting threats in operational event data.

%prep
mkdir -p bundle
tar -xzf %{SOURCE0} -C bundle --strip-components=1

%build

%install
mkdir -p %{buildroot}/opt/cyberglass/bin
mkdir -p %{buildroot}/opt/cyberglass/docs
mkdir -p %{buildroot}/etc/cyberglass
mkdir -p %{buildroot}/etc/cyberglass/rules
mkdir -p %{buildroot}%{_unitdir}

install -m 0755 bundle/bin/cyberglass-server %{buildroot}/opt/cyberglass/bin/cyberglass-server
install -m 0644 bundle/config/cyberglass.toml %{buildroot}/etc/cyberglass/cyberglass.toml
install -m 0644 bundle/LICENSE %{buildroot}/opt/cyberglass/LICENSE
install -m 0644 bundle/README.md %{buildroot}/opt/cyberglass/README.md
cp -a bundle/docs/. %{buildroot}/opt/cyberglass/docs/
cp -a bundle/rules/. %{buildroot}/etc/cyberglass/rules/
install -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/cyberglass.service

%pre
getent group cyberglass >/dev/null || groupadd --system cyberglass
getent passwd cyberglass >/dev/null || useradd --system --gid cyberglass \
    --home-dir /var/lib/cyberglass --shell /sbin/nologin cyberglass

%post
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
fi

%preun
if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now cyberglass.service >/dev/null 2>&1 || :
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
fi

%files
%license /opt/cyberglass/LICENSE
%config(noreplace) /etc/cyberglass/cyberglass.toml
%dir /etc/cyberglass/rules
%config(noreplace) /etc/cyberglass/rules/*
%dir /opt/cyberglass
%dir /opt/cyberglass/bin
/opt/cyberglass/bin/cyberglass-server
%dir /opt/cyberglass/docs
/opt/cyberglass/docs/*
/opt/cyberglass/README.md
%{_unitdir}/cyberglass.service

%changelog
* Fri Oct 30 2026 CyberGlass Engineering <opensource@cyberglass.invalid> - %{version}-%{release}
- Initial Linux RPM package
