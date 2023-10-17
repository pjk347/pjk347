#!/bin/sh

LANG=C
export LANG
alias ls=ls

PS="Docker"
HOST_NAME=`hostname`
DATE=`date +%m%d`

RESULT_FILE=$HOST_NAME"_"$PS"_"$DATE".txt"

##################################################################################
# 준비                                                                             
##################################################################################

echo "***************************************************************************"				> $RESULT_FILE 2>&1
echo "*                                                                         *"				>>  $RESULT_FILE 2>&1
echo "*            Docker Checker                                               *"				>>  $RESULT_FILE 2>&1
echo "*            Version : 1.0                                                *"				>>  $RESULT_FILE 2>&1
echo "*            Docker Version : 24.0.5[Release DATE : 23.07.24]             *"				>>  $RESULT_FILE 2>&1
echo "*            Copyright : Parkjinkuk                                       *"				>>  $RESULT_FILE 2>&1
echo "*                                                                         *"				>>  $RESULT_FILE 2>&1
echo "***************************************************************************"				>>  $RESULT_FILE 2>&1
echo " "													>>  $RESULT_FILE 2>&1
echo ""
echo ""
echo "################# Docker Checker Start ###################"
echo ""
echo ""


#################################################################################
# 시작
#################################################################################

echo "#################################################################################"
echo "#    Docker Checker"
echo "#    Version : 1.0"
echo "#    Docker Version : 24.0.5[Release DATE : 23.07.24]"
echo "#    Copyright : Parkjinkuk"
echo "#################################################################################"


echo "Docker 진단 시작"


echo "도커 최신 패치 적용"
#echo "[01] 도커 최신 패치 적용" >> $RESULT_FILE 2>&1

echo "[01] 수동 : `docker version | grep -A 2 'Server:' | grep -i 'Version'`"  >> $RESULT_FILE 2>&1


echo "[02] 도커 그룹에 불필요한 사용자 제거"
#echo "[02] 도커 그룹에 불필요한 사용자 제거" >> $RESULT_FILE 2>&1

echo "[02] 수동 : `cat /etc/group | grep docker`" >> $RESULT_FILE 2>&1


echo "[03] Docker audit 설정"
#echo "[03] Docker audit 설정" >> $RESULT_FILE 2>&1

if [ -f /etc/audit/audit.rules ]
	then
		if [ `cat /etc/audit/audit.rules | grep /usr/bin/docker | wc -l` -ge 9 ]
			then
				echo "[03] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[03] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[03] 취약" >> $RESULT_FILE 2>&1
fi

echo "/usr/bin/docker 설정"
#echo "/usr/bin/docker"  >> $RESULT_FILE 2>&1

if [ -f /etc/audit/audit.rules ]
	then
		if [ `cat /etc/audit/audit.rules | grep /usr/bin/docker | wc -l` -ge 1 ]
			then
				echo "[03-01] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[03-01] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[03-01] 취약" >> $RESULT_FILE 2>&1
fi

echo "/var/lib/docker 설정"
#echo "/var/lib/docker"  >> $RESULT_FILE 2>&1

if [ -f /etc/audit/audit.rules ]
	then
		if [ `cat /etc/audit/audit.rules | grep /var/lib/docker | wc -l` -ge 1 ]
			then
				echo "[03-02] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[03-02] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[03-02] 취약" >> $RESULT_FILE 2>&1
fi

echo "/etc/docker 설정"
#echo "/etc/docker"  >> $RESULT_FILE 2>&1

if [ -f /etc/audit/audit.rules ]
	then
		if [ `cat /etc/audit/audit.rules | grep /etc/docker | wc -l` -ge 1 ]
			then
				echo "[03-03] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[03-03] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[03-03] 취약" >> $RESULT_FILE 2>&1
fi

echo "OS 별 /docker 설정"
#echo "Ubuntu or Debian"  >> $RESULT_FILE 2>&1

if [ `cat /etc/*release | grep "Ubuntu" | wc -l` -ge 1 -o `cat /etc/*release | grep "Debian" | wc -l` -ge 1 ]
	then
		default_Docker="/etc/default/docker"
	else
		default_Docker="/etc/sysconfig/docker"
fi

if [ -f $default_Docker ]
	then
		if [ -f /etc/audit/audit.rules ]
			then
				if [ `cat /etc/audit/audit.rules | grep $default_Docker | wc -l` -ge 1 ]
					then
						echo "[03-04] 양호" >> $RESULT_FILE 2>&1
					else
						echo "[03-04] 취약" >> $RESULT_FILE 2>&1
				fi
			else
				echo "[03-04] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[03-04] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "/etc/docker/daemon.json 설정"
#echo "/etc/docker/daemon.json"  >> $RESULT_FILE 2>&1

if [ -f /etc/audit/audit.rules ]
	then
		if [ `cat /etc/audit/audit.rules | grep /etc/docker/daemon.json | wc -l` -ge 1 ]
			then
				echo "[03-05] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[03-05] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[03-05] 취약" >> $RESULT_FILE 2>&1
fi

echo "/usr/bin/containerd 설정"
#echo "/usr/bin/containerd"  >> $RESULT_FILE 2>&1

if [ -f /etc/audit/audit.rules ]
	then
		if [ `cat /etc/audit/audit.rules | grep /usr/bin/containerd | wc -l` -ge 1 ]
			then
				echo "[03-06] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[03-06] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[03-06] 취약" >> $RESULT_FILE 2>&1
fi

echo "/usr/bin/runc 설정"
#echo "/usr/bin/runc"  >> $RESULT_FILE 2>&1

if [ -f /etc/audit/audit.rules ]
	then
		if [ `cat /etc/audit/audit.rules | grep /usr/bin/runc | wc -l` -ge 1 ]
			then
				echo "[03-07] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[03-07] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[03-07] 취약" >> $RESULT_FILE 2>&1
fi

echo "docker.service 설정"
#echo "docker.service"  >> $RESULT_FILE 2>&1

if [ `systemctl show -p FragmentPath docker.service | awk 'BEGIN {FS="="} {print $2}' | grep docker.service | wc -l` -eq 0 ]
then
	docker.service=null
else
	docker.service=$(systemctl show -p FragmentPath docker.service | awk 'BEGIN {FS="="} {print $2}' | grep docker.service)
fi

if [ -f $docker.service ]
	then
		if [ -f /etc/audit/audit.rules ]
			then
				if [ `cat /etc/audit/audit.rules | grep docker.service | wc -l` -ge 1 ]
					then
						echo "[03-08] 양호" >> $RESULT_FILE 2>&1
					else
						echo "[03-08] 취약" >> $RESULT_FILE 2>&1
				fi
			else
				echo "[03-08] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[03-08] docker.service 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "docker.socket 설정"
#echo "docker.socket"  >> $RESULT_FILE 2>&1

if [ `systemctl show -p FragmentPath docker.socket | awk 'BEGIN {FS="="} {print $2}' | grep docker.socket | wc -l` -eq 0 ]
then
	docker.socket=null
else
	docker.socket=$(systemctl show -p FragmentPath docker.socket | awk 'BEGIN {FS="="} {print $2}' | grep docker.socket)
fi

if [ -f $docker.socket ]
	then
		if [ -f /etc/audit/audit.rules ]
			then
				if [ `cat /etc/audit/audit.rules | grep docker.socket | wc -l` -ge 1 ]
					then
						echo "[03-09] 양호" >> $RESULT_FILE 2>&1
					else
						echo "[03-09] 취약" >> $RESULT_FILE 2>&1
				fi
			else
				echo "[03-09] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[03-09] docker.socket 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "[04] 주요 설정파일 및 디렉터리 권한 설정"
#echo "[04] 주요 설정파일 및 디렉터리 권한 설정" >> $RESULT_FILE 2>&1

echo "/etc/docker 디렉터리 소유권"
#echo "/etc/docker 디렉터리 소유권"  >> $RESULT_FILE 2>&1

if [ -d /etc/docker ]
	then
		if [ `ls -ld /etc/docker | grep "..........*root root" | wc -l` -ge 1 ]
			then
				echo "[04-01-01] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[04-01-01] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[04-01-01] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "/etc/docker 디렉터리 접근권한"
#echo "/etc/docker 디렉터리 접근권한" >> $RESULT_FILE 2>&1

if [ -d /etc/docker ]
	then
		if [ `ls -ld /etc/docker | grep ".....-..-.." | wc -l` -ge 1 ]
			then
				echo "[04-01-02] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[04-01-02] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[04-01-02] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "daemon.json 파일 소유권"
#echo "daemon.json 파일 소유권" >> $RESULT_FILE 2>&1

if [ -f /etc/docker/daemon.json ]
	then
		if [ `ls -l /etc/docker/daemon.json | grep "..........*root root*" | wc -l` -ge 1 ]
			then
				echo "[04-02-01] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[04-02-01] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[04-02-01] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "daemon.json 파일 접근권한"
#echo "daemon.json 파일 접근권한" >> $RESULT_FILE 2>&1

if [ -f /etc/docker/daemon.json ]
	then
		if [ `ls -l /etc/docker/daemon.json | grep "...-.--.--*" | wc -l` -ge 1 ]
			then
				echo "[04-02-02] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[04-02-02] 양호" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[04-02-01] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "/etc/default/docker 파일 소유권 설정"
#echo "/etc/default/docker 파일 소유권 설정" >> $RESULT_FILE 2>&1

if [ -f $default_Docker ]
	then
		if [ `ls -l $default_Docker | grep "..........*root root*" | wc -l` -ge 1 ]
			then
				echo "[04-03-01] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[04-03-01] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[04-03-01] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "/etc/default/docker 파일 접근권한 설정"
#echo "/etc/default/docker 파일 접근권한 설정" >> $RESULT_FILE 2>&1

if [ -f $default_Docker ]
	then
		if [ `ls -l $default_Docker | grep "...-.--.--*" | wc -l` -ge 1 ]
			then
				echo "[04-03-02] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[04-03-02] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[04-03-02] 수동 확인" >> $RESULT_FILE 2>&1
fi

unset default_Docker

echo "docker.service 소유권 설정"
#echo "docker.service 소유권 설정" >> $RESULT_FILE 2>&1

if [ -f $docker.service ]
	then
		if [ `ls -l $docker.service | grep "..........*root root*" | wc -l` -ge 1 ]
			then
				echo "[04-04-01] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[04-04-01] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[04-04-01] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "docker.service 파일 접근권한"
#echo "docker.service 파일 접근권한" >> $RESULT_FILE 2>&1

if [ -f $docker.service ]
	then
		if [ `ls -l $docker.service | grep "...-.--.--*" | wc -l` -ge 1 ]
			then
				echo "[04-05-02] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[04-05-02] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[04-05-02] 수동 확인" >> $RESULT_FILE 2>&1
fi

unset docker.service

echo "docker.socket 소유권"
#echo "docker.socket 소유권" >> $RESULT_FILE 2>&1

if [ -f $docker.socket ]
	then
		if [ `ls -l $docker.socket | grep "..........*root root*" | wc -l` -ge 1 ]
			then
				echo "[04-06-01] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[04-06-01] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[04-06-01] 수동 확인" >> $RESULT_FILE 2>&1
fi


echo "docker.socket 파일 접근권한"
#echo "docker.socket 파일 접근권한" >> $RESULT_FILE 2>&1

if [ -f $docker.socket ]
	then
		if [ `ls -l $docker.socket | grep "...-.--.--*" | wc -l` -ge 1 ]
			then
				echo "[04-06-02] 양호" >> $RESULT_FILE 2>&1
			else
				echo "[04-06-02] 취약" >> $RESULT_FILE 2>&1
		fi
	else
		echo "[04-06-02] 취약" >> $RESULT_FILE 2>&1
fi

unset docker.socket

echo "/var/run/docker.sock 파일 소유권"
#echo "/var/run/docker.sock 파일 소유권" >> $RESULT_FILE 2>&1

vrdocker=0
rdocker=0

if [ -S /var/run/docker.sock ]
	then
		if [ `ls -l /var/run/docker.sock | grep "..........*root [root or docker]*" | wc -l` -ge 1 ]
			then
				#양호
				vrdocker=1
			else
				#취약
				vrdocker=0
		fi
	else
		vrdocker=2
fi


if [ -S /run/docker.sock ]
	then
		if [ `ls -l /run/docker.sock | grep "..........*root [root or docker]*" | wc -l` -ge 1 ]
			then
				#양호
				rdocker=1
			else
				#취약
				rdocker=0
		fi
	else
		rdocker=2
fi

if [ $vrdocker -eq 0 -o $rdocker -eq 0 ]
	then
		echo "[04-07-01] 취약" >> $RESULT_FILE 2>&1
	elif [ $vrdocker -eq 2 -a $rdocker -eq 2 ]
		then
			echo "[04-07-01] 수동 확인" >> $RESULT_FILE 2>&1
	else
		echo "[04-07-01] 양호 " >> $RESULT_FILE 2>&1
fi

unset vrdocker
unset rdocker	
		
		
echo "/var/run/docker.sock 접근권한 설정"
#echo "/var/run/docker.sock 접근권한 설정" >> $RESULT_FILE 2>&1

vrdocker=0
rdocker=0

if [ -s /var/run/docker.sock ]
	then
		if [ `ls -l /var/run/docker.sock | grep "...-..----*" | wc -l` -ge 1 ]
			then
				#양호
				vrdocker=1
			else
				#취약
				vrdocker=0
		fi
	else
		vrdocker=2
fi

if [  -S /run/docker.sock ]
	then
		if [ `ls -l /run/docker.sock | grep "...-..----*" | wc -l` -ge 1 ]
			then
				#양호
				rdocker=1
			else
				#취약
				rdocker=0
		fi
	else
		rdocker=2
fi

if [ $vrdocker -eq 0 -o $rdocker -eq 0 ]
	then
		echo "[04-07-02] 취약" >> $RESULT_FILE 2>&1
	elif [ $vrdocker -eq 2 -a $rdocker -eq 2 ]
		then
			echo "[04-07-02] 수동 확인" >> $RESULT_FILE 2>&1
	else
		echo "[04-07-02] 양호" >> $RESULT_FILE 2>&1
fi

unset vrdocker
unset rdocker

echo "[05] 주요 시스템 디렉터리 마운트 금지"
#echo "[05] 주요 시스템 디렉터리 마운트 금지" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:DM={{.Mounts}}' | grep map | grep -o 'DM=\[.*' | cut -d '=' -f 2 | wc -l` -eq 0 ]
	then
		echo "[05] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[05] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "[06] 호스트 장치 파일 컨테이너 직접 노출 금지"
#echo "[06] 호스트 장치 파일 컨테이너 직접 노출 금지" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:Devices={{.HostConfig.Devices}}' | grep map | grep -o 'Devices=\[.*' | cut -d '=' -f 2 | wc -l` -eq 0 ]
	then
		echo "[06] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[06] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "[07] 호스트 Network namespaces 공유 금지"
#echo "[07] 호스트 Network namespaces 공유 금지" >> $RESULT_FILE 2>&1

echo "NET"
#echo "NET" >> $RESULT_FILE 2>&1

if [ `docker ps -qa | xargs docker inspect --format '{{.Id}}:NetworkMode={{.HostConfig.NetworkMode}}' | grep -v -E 'NetworkMode=default|NetworkMode=$' | wc -l` -eq 0 ]
	then
		echo "[07-01] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[07-01] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "Pid"
#echo "Pid" >> $RESULT_FILE 2>&1

if [ `docker ps -qa | xargs docker inspect --format '{{.Id}}:PidMode={{.HostConfig.PidMode}}' | grep -E -v 'PidMode=$' | wc -l` -eq 0 ]
	then
		echo "[07-02] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[07-02] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "IPC"
#echo "IPC" >> $RESULT_FILE 2>&1

if [ `docker ps -qa | xargs docker inspect --format '{{.Id}}:IpcMode={{.HostConfig.IpcMode}}' | grep 'IpcMode=host' | wc -l` -eq 0 ]
	then
		echo "[07-03] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[07-03] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "UTS"
#echo "UTS" >> $RESULT_FILE 2>&1

if [ `docker ps -qa | xargs docker inspect --format '{{.Id}}:UTSMode={{.HostConfig.UTSMode}}' | grep 'UTSMode=host' | wc -l` -eq 0 ]
	then
		echo "[07-04] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[07-04] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "UsernsMode"
#echo "UsernsMode" >> $RESULT_FILE 2>&1

if [ `docker ps -qa | xargs docker inspect --format '{{.Id}}:UsernsMode={{.HostConfig.UsernsMode}}' |grep -i host | wc -l` -eq 0 ]
	then
		echo "[07-04] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[07-04] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "User namespaces support"
#echo "User namespaces support" >> $RESULT_FILE 2>&1

container_ids=$(docker ps -q)

for container_id in $container_ids; do
    user_info=$(ps -p $(docker inspect --format='{{.State.Pid}}' "$container_id") -o user)
    container_user=$(echo "$user_info" | awk 'NR==2{print $1}')
    echo "Container ID: $container_id"
    echo "user_info: $container_user"

    if [ "$container_user" == "root" ] 
	then
        echo "[07-05] user namespaces support 사용을 권장하지 않음" >> $RESULT_FILE 2>&1
    else
        echo "[07-05] 수동 확인" >> $RESULT_FILE 2>&1
    fi

echo "[08] Bridge 방식의 default 네트워크 제한"
#echo "[08] Bridge 방식의 default 네트워크 제한" >> $RESULT_FILE 2>&1

if [ `docker network ls -q | xargs docker network inspect --format '{{.Name}}:Bridge={{.Options}}'| grep -E -v "icc:false" | wc -l` -ge 1 ]
	then
		echo "[08] 취약" >> $RESULT_FILE 2>&1
	else
		echo "[08] 수동 확인" >> $RESULT_FILE 2>&1
fi


echo "[09] 불필요한 포트 매핑 금지"
#echo "[09] 불필요한 포트 매핑 금지" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{ .Id }}:Ports={{ .NetworkSettings.Ports }}' | grep Host | wc -l` -eq 0 ]
	then
		echo "[09] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[09] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "[10] 호스트 네트워크 인터페이스 설정"
#echo "[10] 호스트 네트워크 인터페이스 설정" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{ .Id }}:Ports={{ .NetworkSettings.Ports }}' | grep HostIp | grep -v 0.0.0.0 | wc -l` -eq 0 ]
	then
		echo "[10] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[10] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "[10] 호스트 네트워크 인터페이스 설정"
#echo "[10] 호스트 네트워크 인터페이스 설정" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{ .Id }}:Ports={{ .NetworkSettings.Ports }}' | grep HostIp | grep -v 0.0.0.0 | wc -l` -eq 0 ]
	then
		echo "[10] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[10] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "[11] 컨테이너 내 SSH 실행 금지"
#echo "[11] 컨테이너 내 SSH 실행 금지" >> $RESULT_FILE 2>&1

container_ids=$(docker ps -q)

for container_id in $container_ids; do
    ssh_info=$(docker exec $container_id ps -el | grep -i ssh | wc -l)
    echo "Container ID: $container_id"
    echo "ssh_info: $ssh_info"

    if [ "$ssh_info" -eq 0 ] 
	then
        echo "[11] 취약" >> $RESULT_FILE 2>&1
    else
        echo "[11] 수동 확인" >> $RESULT_FILE 2>&1
    fi

echo "[12] Userland 프록시 사용제한"
#echo "[12] Userland 프록시 사용제한" >> $RESULT_FILE 2>&1

if [ `ps aux | grep docker-proxy | wc -l` -eq 1 ]
	then
		echo "[12] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[12] 취약" >> $RESULT_FILE 2>&1
fi

echo "[13] 컨테이너에 docker.sock 마운트 금지"
#echo "[13] 컨테이너에 docker.sock 마운트 금지" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:Sock={{.Mounts}}' | grep map | grep sock | wc -l` -eq 0 ]
	then
		echo "[13] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[13] 취약" >> $RESULT_FILE 2>&1
fi

echo "[14] 컨테이너 크기 설정"
#echo "[14] 컨테이너 크기 설정" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:Volumes={{.Mounts}}' |grep "Type:volume" | wc -l` -eq 0 ]
	then
		echo "[14] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[14] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "[15] 컨테이너 메모리 설정"
#echo "[15] 컨테이너 메모리 설정" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:MEM={{.HostConfig.Memory}}' | grep -E -v MEM=0 | wc -l` -eq 0 ]
	then
		echo "[15] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[15] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "[16] 컨테이너 CPU 설정"
#echo "[16] 컨테이너 CPU 설정" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:CPU={{.HostConfig.CpuShares}}' | grep -E -v CPU=0 | wc -l` -eq 0 ]
	then
		echo "[16] 양호" >> $RESULT_FILE 2>&1
	else
		echo "[16] 수동 확인" >> $RESULT_FILE 2>&1
fi

echo "[17] 컨테이너 프로세스의 리소스 제한"
#echo "[17] 컨테이너 프로세스의 리소스 제한" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:Ulimits={{.HostConfig.Ulimits}}' | grep -E -v "Ulimits=<no value>" | wc -l` -eq 0 ]
	then
		echo "[17] 미적용 수동 확인(참고)" >> $RESULT_FILE 2>&1
	else
		echo "[17] 적용 수동 확인(참고)" >> $RESULT_FILE 2>&1
fi

echo "[18] 컨테이너 프로세스 수 제한"
#echo "[18] 컨테이너 프로세스 수 제한" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:Pidlimit={{.HostConfig.PidsLimit}}' | grep -E -v "Pidlimit=<no value>" | wc -l` -eq 0 ]
	then
		echo "[18] 미적용 수동 확인(참고)" >> $RESULT_FILE 2>&1
	else
		echo "[18] 적용 수동 확인(참고)" >> $RESULT_FILE 2>&1
fi

echo "[19] 컨테이너 재시작 횟수 설정"
#echo "[19] 컨테이너 재시작 횟수 설정" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:Policy={{.HostConfig.RestartPolicy.Name}}:Retry={{.HostConfig.RestartPolicy.MaximumRetryCount}}' | grep -E -v "Policy=no" | wc -l` -eq 0 ]
	then
		echo "[19] 미적용 수동 확인(참고)" >> $RESULT_FILE 2>&1
	else
		echo "[19] 적용 수동 확인(참고)" >> $RESULT_FILE 2>&1
fi

echo "[20] SUID / SGID 제한"
#echo "[20] SUID / SGID 제한" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:Privileged={{.HostConfig.Privileged}}' | grep Privileged=true | wc -l` -eq 0 ]
	then
		echo "[20] 양호 (참고)" >> $RESULT_FILE 2>&1
	else
		echo "[20] 수동 확인(참고)" >> $RESULT_FILE 2>&1
fi

echo "[21] 컨테이너 Root FileSystem 읽기 권한 설정"
#echo "[21] 컨테이너 Root FileSystem 읽기 권한 설정" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:Readonly={{.HostConfig.ReadonlyRootfs}}' | grep Readonly=false | wc -l` -eq 0 ]
	then
		echo "[21] 양호 (참고)" >> $RESULT_FILE 2>&1
	else
		echo "[21] 수동 확인(참고)" >> $RESULT_FILE 2>&1
fi

echo "[22] 컨테이너 SELinux 설정"
#echo "[22] 컨테이너 SELinux 설정" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:SELinux={{.HostConfig.SecurityOpt}}' | grep "SELinux=<no value>" | wc -l` -eq 0 ]
	then
		echo "[22] 양호 (참고)" >> $RESULT_FILE 2>&1
	else
		echo "[22] 수동 확인(참고)" >> $RESULT_FILE 2>&1
fi

echo "[23] 컨테이너 커널 Capabilities 제한"
#echo "[23] 컨테이너 커널 Capabilities 제한" >> $RESULT_FILE 2>&1

if [ `docker ps -qa |xargs docker inspect --format '{{.Id}}:Add={{.HostConfig.CapAdd}}:Drop={{.HostConfig.CapDrop}}' | grep "Add=<no value>" | wc -l` -eq 0 ]
	then
		echo "[23] 양호 (참고)" >> $RESULT_FILE 2>&1
	else
		echo "[23] 수동 확인(참고)" >> $RESULT_FILE 2>&1
fi

echo "[24] 로그 레벨 설정"
#echo "[24] 로그 레벨 설정" >> $RESULT_FILE 2>&1

log_driver=$(docker info --format 'Log={{.LoggingDriver}}')

if [ "$log_driver" == "Log=json-file" ]
	then
		echo "[24] 양호 (참고)" >> $RESULT_FILE 2>&1
	else
		echo "[24] 수동 확인(참고)" >> $RESULT_FILE 2>&1
fi

echo "End" >> $RESULT_FILE 2>&1
	
echo "Docker 진단 종료"

