import asyncio
from tcputils import *
import random


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return

        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # Cliente está iniciando uma nova conexão
            id_conexao_com_seq = (src_addr, src_port, dst_addr, dst_port, seq_no)
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao_com_seq)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        src_addr, src_port, dst_addr, dst_port, client_isn = id_conexao
        self.client_isn = client_isn
        self.ack_no = self.client_isn + 1
        self.seq_no = random.randint(0, 0xFFFF)

        self.unacked_segment = None
        self.unacked_seq = None
        self.timer = None
        self.TIMEOUT = 1  # segundos

        self.cwnd = 1  # janela de congestionamento em MSS
        self.ssthresh = 1000  # threshold arbitrário, pode ser ignorado para AIMD simples
        self.enviados_sem_ack = 0

        self._enviar_synack()
        self.seq_no += 1  # ← ESSENCIAL: conta o byte virtual do SYN

    def _enviar_synack(self):
        src_addr, src_port, dst_addr, dst_port, _ = self.id_conexao
        header = make_header(
            src_port=dst_port,
            dst_port=src_port,
            seq_no=self.seq_no,
            ack_no=self.ack_no,
            flags=FLAGS_SYN | FLAGS_ACK
        )
        header = fix_checksum(header, src_addr, dst_addr)
        self.servidor.rede.enviar(header, src_addr)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port, _ = self.id_conexao

        if flags & FLAGS_FIN:
            # Cliente quer fechar a conexão

            # Envia ACK confirmando o FIN
            ack_header = make_header(
                src_port=dst_port,
                dst_port=src_port,
                seq_no=self.seq_no,
                ack_no=seq_no + 1,
                flags=FLAGS_ACK
            )
            ack_header = fix_checksum(ack_header, src_addr, dst_addr)
            self.servidor.rede.enviar(ack_header, src_addr)

            # Informa a aplicação que a conexão foi encerrada
            if self.callback:
                self.callback(self, b'')

        elif len(payload) > 0:
            # Recebeu dados com ACK
            if seq_no == self.ack_no:
                self.ack_no += len(payload)
                if self.callback:
                    self.callback(self, payload)

            # Envia ACK dos dados recebidos
            ack_header = make_header(
                src_port=dst_port,
                dst_port=src_port,
                seq_no=self.seq_no,
                ack_no=self.ack_no,
                flags=FLAGS_ACK
            )
            ack_header = fix_checksum(ack_header, src_addr, dst_addr)
            self.servidor.rede.enviar(ack_header, src_addr)

        else:
            # Apenas um ACK puro: ignora
            pass

        # Trata ACK recebido
        if flags & FLAGS_ACK:
            if self.unacked_seq is not None and ack_no > self.unacked_seq:
                if self.timer:
                    self.timer.cancel()
                    self.timer = None
                self.unacked_segment = None
                self.unacked_seq = None
                self.enviados_sem_ack -= 1
                if self.enviados_sem_ack == 0:
                    self.cwnd += 1  # AIMD: aumenta janela

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port, _ = self.id_conexao

        i = 0
        while i < len(dados):
            if self.enviados_sem_ack < self.cwnd:
                parte = dados[i:i+MSS]
                header = make_header(
                    src_port=dst_port,
                    dst_port=src_port,
                    seq_no=self.seq_no,
                    ack_no=self.ack_no,
                    flags=FLAGS_ACK
                )
                segmento = header + parte
                segmento = fix_checksum(segmento, src_addr, dst_addr)
                self.servidor.rede.enviar(segmento, src_addr)

                self.unacked_segment = segmento
                self.unacked_seq = self.seq_no
                self._start_timer()

                self.seq_no += len(parte)
                self.enviados_sem_ack += 1
            else:
                break
            i += len(parte)  # <-- ESSENCIAL!

    def _start_timer(self):
        if self.timer:
            self.timer.cancel()
        loop = asyncio.get_event_loop()
        self.timer = loop.call_later(self.TIMEOUT, self._timeout)

    def _timeout(self):
        # Retransmite segmento não confirmado
        if self.unacked_segment:
            src_addr, src_port, dst_addr, dst_port, _ = self.id_conexao
            print("Timeout! Retransmitindo segmento.")
            self.servidor.rede.enviar(self.unacked_segment, src_addr)
            self._start_timer()
            self.cwnd = max(1, self.cwnd // 2)  # AIMD: reduz janela pela metade
            self.enviados_sem_ack = 0  # reinicia contagem

    def fechar(self):
        src_addr, src_port, dst_addr, dst_port, _ = self.id_conexao
        fin_header = make_header(
            src_port=dst_port,
            dst_port=src_port,
            seq_no=self.seq_no,
            ack_no=self.ack_no,
            flags=FLAGS_FIN
        )
        fin_header = fix_checksum(fin_header, src_addr, dst_addr)
        self.servidor.rede.enviar(fin_header, src_addr)
        self.seq_no += 1  # Conta o FIN como 1 byte enviado

